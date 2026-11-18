import {
  Activity,
  ArrowDown,
  ArrowUp,
  Copy,
  Globe,
  Loader2,
  Power,
  RefreshCw,
  Route,
  ShieldAlert,
  ShieldCheck,
  Timer,
  Unplug,
} from "lucide-react";
import type { BusyKind } from "../hooks/useVpn";
import type { Mode, VpnState } from "../types";
import { formatBytes, formatUptime } from "../lib/format";

interface ConnectPanelProps {
  state: VpnState;
  busy: BusyKind;
  mode: Mode;
  global: boolean;
  onModeChange: (mode: Mode) => void;
  onGlobalChange: (value: boolean) => void;
  onToggle: () => void;
  onRecheck: () => void;
  onRelaunchAdmin: () => void;
  onCopy: (value: string) => void;
}

function orbState(state: VpnState): "connected" | "connecting" | "disconnecting" | "error" | "idle" {
  if (state.phase === "connected") return "connected";
  if (state.phase === "connecting") return "connecting";
  if (state.phase === "disconnecting") return "disconnecting";
  if (state.phase === "error") return "error";
  return "idle";
}

const STATUS: Record<string, string> = {
  connected: "Защищено",
  connecting: "Подключение…",
  disconnecting: "Отключение…",
  error: "Ошибка",
  idle: "Готово к подключению",
};

export function ConnectPanel({
  state,
  busy,
  mode,
  global,
  onModeChange,
  onGlobalChange,
  onToggle,
  onRecheck,
  onRelaunchAdmin,
  onCopy,
}: ConnectPanelProps) {
  const profile = state.profile;
  const connecting = busy === "connect" || state.phase === "connecting";
  const disconnecting = busy === "disconnect" || state.phase === "disconnecting";
  const disabled = connecting || disconnecting;
  const orb = orbState(state);

  const exitIp = state.exit?.ip ?? state.exit?.error ?? "—";
  const exitChecked = state.exit?.checkedAt
    ? new Date(state.exit.checkedAt * 1000).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" })
    : "";

  const routePills = profile
    ? [
        { key: "ru", title: "RU", value: profile.ru.label, kind: profile.ru.kind },
        { key: "world", title: "Мир", value: profile.nonRu.label, kind: profile.nonRu.kind },
        { key: "private", title: "Локально", value: profile.private.label, kind: profile.private.kind },
      ]
    : [];

  return (
    <section className="card hero">
      <div className="hero-left">
        <div className="hero-kicker">СОСТОЯНИЕ</div>
        <button
          className="orb"
          data-state={orb}
          onClick={onToggle}
          disabled={disabled}
          aria-label={state.connected ? "Отключиться" : "Подключиться"}
        >
          <span className="orb-ring" />
          <span className="orb-core">
            {connecting || disconnecting ? (
              <Loader2 size={42} strokeWidth={1.8} />
            ) : (
              <Power size={42} strokeWidth={1.8} />
            )}
          </span>
        </button>
        <div className={`status-label ${state.connected ? "on" : ""} ${state.phase === "error" ? "bad" : ""}`}>
          {connecting ? "Подключение…" : disconnecting ? "Отключение…" : STATUS[orb]}
        </div>
        <div className="status-profile">
          {profile ? profile.name : "Профиль не выбран"}
          {state.global ? " · весь трафик" : ""}
        </div>
      </div>

      <div className="hero-right">
        <div className="mode-block">
          <div>
            <div className="mode-label">РЕЖИМ ПОДКЛЮЧЕНИЯ</div>
            <div className="mode-switch" style={{ marginTop: 8 }}>
              <button
                className={`mode-btn ${mode === "proxy" ? "active" : ""}`}
                onClick={() => onModeChange("proxy")}
                disabled={disabled}
              >
                <Globe size={15} />
                Системный прокси
              </button>
              <button
                className={`mode-btn ${mode === "tun" ? "active" : ""}`}
                onClick={() => onModeChange("tun")}
                disabled={disabled}
              >
                <ShieldCheck size={15} />
                VPN · TUN
              </button>
            </div>
          </div>
          <div style={{ textAlign: "right", minWidth: 180 }}>
            <div className="mode-label">ЛОКАЛЬНЫЕ ПОРТЫ</div>
            <div style={{ marginTop: 9, fontFamily: "var(--font-mono)", fontSize: 11.5, color: "rgba(238,241,255,.55)" }}>
              SOCKS5 <b style={{ color: "#dfe4ff" }}>127.0.0.1:{state.ports.socks}</b>
              <br />
              HTTP <b style={{ color: "#dfe4ff" }}>127.0.0.1:{state.ports.http}</b>
            </div>
          </div>
        </div>

        <div className="stat-grid">
          <div className="stat clickable" onClick={() => (state.exit?.ip ? onCopy(state.exit.ip) : onRecheck())} title="Проверить внешний IP">
            <div className="stat-label">Внешний IP</div>
            <div className="stat-value mono" style={{ color: state.exit?.ip ? "#7ff0c2" : undefined }}>
              {exitIp}
            </div>
            <div className="stat-sub">{exitChecked ? `обновлено ${exitChecked}` : "проверка…"}</div>
          </div>
          <div className="stat">
            <div className="stat-label">
              <Timer size={11} style={{ verticalAlign: -1, marginRight: 4 }} />
              Время
            </div>
            <div className="stat-value mono">{formatUptime(state.stats.uptime)}</div>
            <div className="stat-sub">текущая сессия</div>
          </div>
          <div className="stat">
            <div className="stat-label">
              <Activity size={11} style={{ verticalAlign: -1, marginRight: 4 }} />
              Соединения
            </div>
            <div className="stat-value">{state.stats.sessions}</div>
            <div className="stat-sub">поллинг {state.stats.polls}</div>
          </div>
          <div className="stat">
            <div className="stat-label">
              <ArrowDown size={11} style={{ verticalAlign: -1, marginRight: 4 }} />
              <ArrowUp size={11} style={{ verticalAlign: -1 }} />
            </div>
            <div className="stat-value mono">
              {formatBytes(state.stats.down)} <span style={{ opacity: 0.5 }}>/</span> {formatBytes(state.stats.up)}
            </div>
            <div className="stat-sub">приём / передача</div>
          </div>
        </div>

        {mode === "tun" && !state.admin && (
          <div className="warning-strip">
            <ShieldAlert size={18} style={{ flex: "0 0 auto" }} />
            <span className="grow">
              TUN-режим создаёт виртуальный адаптер и меняет маршруты. Нужно перезапустить приложение
              от имени администратора.
            </span>
            <button className="btn ghost" onClick={onRelaunchAdmin}>
              Перезапустить
            </button>
          </div>
        )}

        {mode === "tun" && state.admin && (
          <div className="route-summary">
            <span className={`route-pill ${state.tun.running ? "mint" : ""}`}>
              <span className="dot" />
              sing-box {state.tun.available ? "1.14.3" : "не найден"}: {state.tun.running ? "адаптер активен" : "готов"}
            </span>
            <span className="route-pill">
              <span className="dot" />
              Адаптер <b>fimdi-tun</b>
            </span>
          </div>
        )}

        {profile && (
          <div className="route-summary">
            {routePills.map((pill) => (
              <span className={`route-pill ${pill.kind === "direct" ? "rose" : ""}`} key={pill.key}>
                <span className="dot" />
                {pill.title} <b>{pill.value}</b>
              </span>
            ))}
            <span className="route-pill" title="Узлы, которые использует профиль">
              <Route size={12} />
              маршрут <b>{profile.primaryLabel}</b>
            </span>
          </div>
        )}

        <div className="toggle-row">
          <div className="toggle-row-text">
            <div className="toggle-row-title">Весь трафик через выбранный выход</div>
            <div className="toggle-row-sub">
              Отключает умный split: RU-сайты тоже пойдут через выход профиля. Локальные адреса
              остаются прямыми.
            </div>
          </div>
          <button
            className={`switch ${global ? "on" : ""}`}
            onClick={() => onGlobalChange(!global)}
            disabled={disabled}
            aria-label="Весь трафик через выбранный выход"
          />
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <button className="btn" onClick={onRecheck} disabled={!state.connected}>
            <RefreshCw size={14} />
            Перепроверить IP
          </button>
          <button className="btn ghost" onClick={() => onCopy(`${state.ports.http}`)} disabled={!state.connected}>
            <Copy size={14} />
            Скопировать порт прокси
          </button>
          {state.connected ? (
            <span className="chip mint">
              <Unplug size={12} />
              сессия активна
            </span>
          ) : null}
        </div>
      </div>
    </section>
  );
}
