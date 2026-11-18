import { Power, RefreshCw, ScrollText, ShieldCheck, SlidersHorizontal, ShieldAlert } from "lucide-react";
import type { VpnState } from "../types";
import { PHASE_SHORT, formatUptime } from "../lib/format";

export type Tab = "vpn" | "subscription" | "logs";

interface SidebarProps {
  state: VpnState | null;
  tab: Tab;
  onTab: (tab: Tab) => void;
  onRefresh: () => void;
  busy: string | null;
}

function dotClass(state: VpnState): string {
  if (state.phase === "connected") return "status-dot on";
  if (state.phase === "connecting" || state.phase === "disconnecting") return "status-dot busy";
  if (state.phase === "error") return "status-dot bad";
  return "status-dot";
}

export function Sidebar({ state, tab, onTab, onRefresh, busy }: SidebarProps) {
  const nav = [
    { id: "vpn" as Tab, label: "Подключение", icon: ShieldCheck },
    { id: "subscription" as Tab, label: "Подписка", icon: SlidersHorizontal },
    { id: "logs" as Tab, label: "Журнал", icon: ScrollText },
  ];

  const profileName = state?.profile?.name ?? state?.profileId ?? "—";
  const statusText =
    state?.phase === "connected"
      ? `${formatUptime(state.stats.uptime)} · ${state.exit?.ip ?? "проверка…"}`
      : state?.phase === "connecting"
        ? "Поднимаем туннель…"
        : state?.phase === "disconnecting"
          ? "Закрываем сессию…"
          : state?.phase === "error"
            ? "Проверьте лог и профиль"
            : state?.subscription
              ? "Профиль выбран"
              : "Загрузите подписку";

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">
          <Power size={19} strokeWidth={2.6} />
        </div>
        <div className="brand-text">
          <div className="brand-name">FIMDI VPN</div>
          <div className="brand-sub">desktop</div>
        </div>
      </div>

      <div className="status-card">
        <div className="status-row">
          <span className={dotClass(state ?? { phase: "idle" } as VpnState)} />
          <span className="status-title">{state ? PHASE_SHORT[state.phase] : "Запуск…"}</span>
        </div>
        <div className="status-sub">
          {profileName}
          <br />
          {statusText}
        </div>
      </div>

      <nav className="nav">
        {nav.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              className={`nav-item ${tab === item.id ? "active" : ""}`}
              onClick={() => onTab(item.id)}
            >
              <Icon size={17} />
              <span className="nav-label">{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="sidebar-spacer" />

      <div className="side-footer">
        {state?.admin ? (
          <span className="chip mint">
            <ShieldCheck size={13} />
            <span className="chip-text">Права администратора</span>
          </span>
        ) : (
          <span className="chip amber">
            <ShieldAlert size={13} />
            <span className="chip-text">TUN требует admin</span>
          </span>
        )}
        <span className="chip">
          <span className="chip-text">v{state?.version ?? "…"}</span>
        </span>
        <button
          className="icon-btn ghost"
          onClick={onRefresh}
          disabled={busy !== null}
          title="Обновить состояние"
          style={{ width: "100%", marginTop: 4 }}
        >
          <RefreshCw size={14} />
          <span className="nav-label">Обновить</span>
        </button>
      </div>
    </aside>
  );
}
