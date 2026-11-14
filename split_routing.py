"""Split-routing по RU / non-RU / private.

Списки (GeoIP RU + домены) скачиваются с сервера или читаются из файлов.
Клиент матчит локально и выбирает маршрут/exit для каждой SOCKS-сессии.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import random
from typing import Iterable, Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen

logger = logging.getLogger("vpn-routing")

MAX_HOPS = 3


def validate_route_hops(hops: list[dict], known_node_ids: Optional[set[str]] = None,
                        known_node_urls: Optional[dict[str, str]] = None) -> list[dict]:
    """Проверяет описание маршрута и возвращает список проблем.

    Каждая проблема: {"level": "error"|"warning", "message": str}.
    Ошибки не дают панели сохранить заведомо нерабочий маршрут;
    предупреждения показывают, что клиент будет исключать повторы узлов
    и/или сокращать цепочку.
    """
    issues: list[dict] = []

    def add(level: str, message: str) -> None:
        issues.append({"level": level, "message": message})

    if not hops:
        add("error", "Маршрут должен содержать хотя бы один hop")
        return issues
    if len(hops) > MAX_HOPS:
        add("error", f"Максимум {MAX_HOPS} hop-а, указано {len(hops)}")

    known_urls = {str(v).rstrip("/"): str(k) for k, v in (known_node_urls or {}).items()}
    used_at: dict[str, int] = {}
    all_keys: set[str] = set()
    url_ids: dict[str, set[str]] = {}

    for i, hop in enumerate(hops, 1):
        raw = [str(c).strip() for c in (hop.get("candidates") or []) if str(c).strip()]
        if not raw:
            add("error", f"Hop {i}: список кандидатов пуст")
            continue

        seen: set[str] = set()
        hop_keys: set[str] = set()
        for cand in raw:
            if cand in seen:
                add("warning", f"Hop {i}: кандидат {cand} повторяется, будет учтён один раз")
                continue
            seen.add(cand)

            if cand.startswith("http://") or cand.startswith("https://"):
                url = cand.rstrip("/")
                node_id = known_urls.get(url, "")
                if not node_id:
                    add("warning", f"Hop {i}: URL {url} не совпадает ни с одним узлом subscription.nodes")
                key = node_id or url
            else:
                node_id = cand
                url = (known_node_urls or {}).get(cand, "")
                if known_node_ids is not None and cand not in known_node_ids:
                    add("error", f"Hop {i}: неизвестный узел {cand}")
                    continue
                key = cand

            if key in used_at and used_at[key] != i:
                add("warning", f"Hop {i}: узел {key} уже есть в Hop {used_at[key]}; "
                               "клиент не будет использовать его дважды")
            else:
                used_at[key] = i
            hop_keys.add(key)
            all_keys.add(key)
            if url:
                url_ids.setdefault(url, set()).add(key)

        if not hop_keys:
            add("error", f"Hop {i}: нет валидных кандидатов")

    if len(hops) <= MAX_HOPS and all_keys and len(all_keys) < len(hops):
        add("error",
            f"Невозможно построить цепочку: hop-ов {len(hops)}, "
            f"а уникальных узлов только {len(all_keys)} "
            f"({', '.join(sorted(all_keys))})")

    for url, ids in url_ids.items():
        if len(ids) > 1:
            add("warning", f"Разные node_id указывают на один URL {url}: "
                           f"{', '.join(sorted(ids))}; клиент не будет использовать их вместе")

    return issues


DEFAULT_PRIVATE = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
]

DEFAULT_DIRECT_DOMAINS = ["localhost", "local", "lan", "home.arpa"]
DEFAULT_RU_SUFFIXES = ["ru", "xn--p1ai", "su", "vk.com", "yandex.com", "yandex.net", "2gis.com"]


def load_text(source: str, timeout: int = 15) -> str:
    if not source:
        return ""
    parsed = urlparse(source)
    if parsed.scheme in ("http", "https"):
        req = Request(source, headers={"User-Agent": "vpn-client/1.0"})
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace")
    with open(source, "r", encoding="utf-8") as f:
        return f.read()


def parse_domains(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if not line:
            continue
        for part in line.replace(",", " ").split():
            part = part.strip().rstrip(".")
            if part.startswith("*."):
                part = part[2:]
            part = part.lstrip(".")
            if part and not part.startswith("!"):
                out.append(part)
    return out


def parse_cidrs(text: str) -> list[ipaddress._BaseNetwork]:
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        token = line.split()[0].strip()
        try:
            out.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            continue
    return out


class Ruleset:
    def __init__(self, ru_cidrs: Iterable[str] = (), ru_domains: Iterable[str] = (),
                 direct_domains: Iterable[str] = (), private_cidrs: Iterable[str] = DEFAULT_PRIVATE):
        self.ru_nets = []
        for cidr in ru_cidrs:
            try:
                self.ru_nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass
        self.private_nets = []
        for cidr in list(private_cidrs or []) + DEFAULT_PRIVATE:
            try:
                self.private_nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass
        self.ru_domains = [d.lower().lstrip(".") for d in
                           list(DEFAULT_RU_SUFFIXES) + [d for d in ru_domains if d]]
        # убрать дубликаты, сохранив порядок
        self.ru_domains = list(dict.fromkeys(self.ru_domains))
        self.direct_domains = [d.lower().lstrip(".") for d in
                               list(direct_domains or []) + DEFAULT_DIRECT_DOMAINS]

    @classmethod
    def from_config(cls, rules_cfg: dict) -> "Ruleset":
        rules_cfg = rules_cfg or {}
        geoip = rules_cfg.get("geoip") or rules_cfg.get("geoip_url") or ""
        domains = rules_cfg.get("domains") or rules_cfg.get("domains_url") or ""
        geoip_text = ""
        domains_text = ""
        try:
            geoip_text = load_text(geoip)
        except Exception as exc:
            logger.warning("geoip load failed (%s): %s", geoip, exc)
        try:
            domains_text = load_text(domains)
        except Exception as exc:
            logger.warning("domains load failed (%s): %s", domains, exc)
        extra_ru = rules_cfg.get("ru_domains") or []
        extra_direct = rules_cfg.get("direct_domains") or []
        direct_text = rules_cfg.get("direct") or ""
        if direct_text:
            try:
                extra_direct = list(extra_direct) + parse_domains(load_text(direct_text))
            except Exception:
                pass
        return cls(
            ru_cidrs=parse_cidrs(geoip_text) if geoip_text else [],
            ru_domains=parse_domains(domains_text) + list(extra_ru),
            direct_domains=list(extra_direct),
        )

    @staticmethod
    def _match_domain(host: str, domains: Iterable[str]) -> bool:
        host = host.lower().rstrip(".")
        for d in domains:
            if host == d or host.endswith("." + d):
                return True
        return False

    def classify(self, host: str) -> str:
        """Возвращает ru | private | non_ru."""
        host = (host or "").strip().lower().rstrip(".")
        if not host:
            return "non_ru"
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            if self._match_domain(host, self.direct_domains):
                return "private"
            if self._match_domain(host, self.ru_domains):
                return "ru"
            return "non_ru"
        for net in self.private_nets:
            if ip.version == net.version and ip in net:
                return "private"
        for net in self.ru_nets:
            if ip.version == net.version and ip in net:
                return "ru"
        return "non_ru"


class SplitRouter:
    def __init__(self, cfg: dict):
        split = cfg.get("split_routing") or {}
        self.enabled = bool(split.get("enabled", False))
        self.default = str(split.get("default", "non_ru"))
        self.actions = split.get("actions") or {}
        self.ruleset = Ruleset.from_config(split.get("rules") or {})
        self.node_urls: dict[str, str] = {}
        self.url_nodes: dict[str, str] = {}
        for node in cfg.get("nodes") or []:
            if node.get("id") and node.get("url"):
                nid = str(node["id"])
                url = str(node["url"]).rstrip("/")
                self.node_urls[nid] = url
                self.url_nodes[url] = nid
        # Если узлы не в подписке — используем server_urls как кандидатов по порядку.
        self.fallback_urls = list(cfg.get("client", {}).get("server_urls") or [])
        self.routes: dict[str, list[dict]] = {}
        # Новый формат: каталог маршрутов из конструктора админки.
        for route in cfg.get("routes") or []:
            name = route.get("name")
            if name:
                self.routes[str(name)] = route.get("hops") or []
        # Старый формат: profiles[].routes (не перетирает новые определения).
        for profile in cfg.get("profiles") or []:
            for route in profile.get("routes") or []:
                name = route.get("name")
                if name and str(name) not in self.routes:
                    self.routes[str(name)] = route.get("hops") or []
        self._rr: dict[str, int] = {}
        self._warned_multi = False
        # Явно сообщаем о проблемных маршрутах при старте клиента.
        self.validation: dict[str, list[dict]] = {}
        for name, hops in self.routes.items():
            issues = validate_route_hops(hops, set(self.node_urls), self.node_urls)
            self.validation[str(name)] = issues
            for issue in issues:
                log = logger.error if issue.get("level") == "error" else logger.warning
                log("route %r: %s", name, issue.get("message"))

    def _route_hops(self, route_name: str, available: Optional[set[str]]):
        """Возвращает [ (node_id, url), ... ] с выбором кандидатов по стратегии.

        Цепочка выбирается целиком: клиент не допускает повтор одного и того
        же узла (node_id или URL) на разных hop-ах. Если различных узлов
        меньше, чем hop-ов, используется самый длинный валидный префикс.
        """
        hops = self.routes.get(route_name) or []
        if not hops:
            logger.error("route %r: no hops defined", route_name)
            return []
        if len(hops) > MAX_HOPS:
            logger.warning("route %r has %d hops; max is %d, using first %d",
                           route_name, len(hops), MAX_HOPS, MAX_HOPS)
            hops = hops[:MAX_HOPS]

        pools: list[list[tuple[str, str]]] = []
        strategies: list[str] = []
        for i, hop in enumerate(hops, 1):
            candidates = []
            seen: set[str] = set()
            for cand in hop.get("candidates") or []:
                cand = str(cand).strip()
                if not cand:
                    continue
                if cand.startswith("http://") or cand.startswith("https://"):
                    url = cand.rstrip("/")
                    node_id = self.url_nodes.get(url, "")
                else:
                    node_id = cand
                    url = self.node_urls.get(cand, "")
                if not url:
                    logger.warning("route %r: hop %d candidate %r has no URL, skipped",
                                   route_name, i, cand)
                    continue
                key = node_id or url
                if key in seen:
                    continue
                seen.add(key)
                candidates.append((node_id, url))
            if not candidates:
                candidates = [(self.url_nodes.get(u, ""), u) for u in self.fallback_urls]
            if not candidates:
                logger.error("route %r: hop %d has no usable candidates", route_name, i)
                return []
            pools.append(candidates)
            strategies.append(str(hop.get("strategy", "round")).lower())

        chain = self._pick_chain(route_name, pools, strategies, available)
        if not chain:
            logger.error("route %r: cannot build a chain without repeating nodes", route_name)
        return chain

    def _pick_chain(self, route_name: str, pools: list[list[tuple[str, str]]],
                    strategies: list[str], available: Optional[set[str]]
                    ) -> list[tuple[str, str]]:
        """Выбирает цепочку без повторяющихся node_id/URL с backtracking."""
        filtered: list[list[tuple[str, str]]] = []
        for pool in pools:
            usable = [pair for pair in pool if not available or pair[1] in available]
            filtered.append(usable or list(pool))

        requested = len(filtered)
        limit = min(requested, MAX_HOPS)
        for length in range(limit, 0, -1):
            chain = self._search_chain(route_name, filtered, strategies, length)
            if not chain:
                continue
            for i in range(length):
                if strategies[i] != "random" and filtered[i]:
                    key = f"{route_name}:{i}"
                    self._rr[key] = (self._rr.get(key, 0) + 1) % len(filtered[i])
            if length < requested:
                logger.warning(
                    "route %r: using %d hop(s) instead of %d — not enough distinct nodes",
                    route_name, length, requested,
                )
            return chain
        return []

    def _search_chain(self, route_name: str, pools: list[list[tuple[str, str]]],
                      strategies: list[str], length: int
                      ) -> list[tuple[str, str]]:
        used_ids: set[str] = set()
        used_urls: set[str] = set()
        chosen: list[tuple[str, str]] = []

        def dfs(i: int):
            if i == length:
                return list(chosen)
            pool = pools[i]
            size = len(pool)
            if strategies[i] == "random":
                order = list(range(size))
                random.shuffle(order)
            else:
                start = self._rr.get(f"{route_name}:{i}", 0) % size
                order = [(start + k) % size for k in range(size)]
            for pos in order:
                node_id, url = pool[pos]
                key = node_id or url
                if key in used_ids or (url and url in used_urls):
                    continue
                used_ids.add(key)
                if url:
                    used_urls.add(url)
                chosen.append((node_id, url))
                result = dfs(i + 1)
                if result is not None:
                    return result
                chosen.pop()
                used_ids.discard(key)
                if url:
                    used_urls.discard(url)
            return None

        return dfs(0) or []

    def route_for(self, host: str, available: Optional[set[str]] = None
                  ) -> tuple:
        """Возвращает (mode, entry_url, route_ids, category[, reason]).

        mode = tunnel | direct | error.
        route_ids пуст для direct и односкачковых маршрутов; для relay
        содержит полную цепочку node_id. В режиме error пятый элемент —
        причина, которую клиент пишет в лог и отдаёт SOCKS-ошибку.
        """
        if not self.enabled:
            return "tunnel", None, (), None
        category = self.ruleset.classify(host)
        action = self.actions.get(category) or self.actions.get(self.default) or {}
        if action.get("direct"):
            return "direct", None, (), category
        route_name = action.get("route")
        if not route_name:
            return "tunnel", None, (), category
        hops = self._route_hops(route_name, available)
        if not hops:
            reason = (f"route {route_name!r} cannot be built "
                      f"(недостаточно разных доступных узлов)")
            logger.error("%s for host %s", reason, host)
            return "error", None, (), category, reason
        entry_url = hops[0][1]
        if len(hops) == 1:
            return "tunnel", entry_url, (), category
        if any(not nid for nid, _ in hops):
            logger.warning("route %r has hops without node_id; relay disabled, using exit URL",
                           route_name)
            return "tunnel", hops[-1][1], (), category
        return "tunnel", entry_url, tuple(nid for nid, _ in hops), category
