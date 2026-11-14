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
        for profile in cfg.get("profiles") or []:
            for route in profile.get("routes") or []:
                if route.get("name"):
                    self.routes[str(route["name"])] = route.get("hops") or []
        self._rr: dict[str, int] = {}
        self._warned_multi = False

    def _route_hops(self, route_name: str, available: Optional[set[str]]):
        """Возвращает [ (node_id, url), ... ] с выбором кандидатов по стратегии."""
        hops = self.routes.get(route_name) or []
        if not hops:
            return []
        resolved = []
        for i, hop in enumerate(hops):
            candidates = []
            for cand in hop.get("candidates") or []:
                cand = str(cand)
                if cand.startswith("http://") or cand.startswith("https://"):
                    url = cand.rstrip("/")
                    node_id = self.url_nodes.get(url, "")
                else:
                    node_id = cand
                    url = self.node_urls.get(cand, "")
                if url:
                    candidates.append((node_id, url))
            if not candidates:
                candidates = [(self.url_nodes.get(u, ""), u) for u in self.fallback_urls]
            if not candidates:
                return []
            strategy = str(hop.get("strategy", "round")).lower()
            resolved.append(self._pick_pair(f"{route_name}:{i}", candidates, strategy, available))
        return resolved

    def _pick_pair(self, key: str, pairs: list[tuple[str, str]], strategy: str,
                   available: Optional[set[str]]) -> tuple[str, str]:
        pool = [p for p in pairs if not available or p[1] in available]
        if not pool:
            pool = pairs
        if strategy == "random":
            return random.choice(pool)
        idx = self._rr.get(key, 0)
        self._rr[key] = idx + 1
        return pool[idx % len(pool)]

    def route_for(self, host: str, available: Optional[set[str]] = None
                  ) -> tuple[str, Optional[str], tuple[str, ...], Optional[str]]:
        """Возвращает (mode, entry_url, route_ids, category).

        mode = tunnel | direct. route_ids пуст для direct и односкачковых
        маршрутов; для relay содержит полную цепочку node_id.
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
            return "tunnel", None, (), category
        entry_url = hops[0][1]
        if len(hops) == 1:
            return "tunnel", entry_url, (), category
        if len(hops) > 3:
            logger.warning("route %r has %d hops; max is 3, using first 3", route_name, len(hops))
            hops = hops[:3]
        if any(not nid for nid, _ in hops):
            logger.warning("route %r has hops without node_id; relay disabled, using exit URL",
                           route_name)
            return "tunnel", hops[-1][1], (), category
        return "tunnel", entry_url, tuple(nid for nid, _ in hops), category
