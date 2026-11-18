import { useState } from "react";
import { Globe, Link2, Loader2, RefreshCw, ShieldAlert, Users } from "lucide-react";
import type { BusyKind } from "../hooks/useVpn";
import type { VpnState } from "../types";
import { formatDateTime } from "../lib/format";

interface SubscriptionPanelProps {
  state: VpnState;
  busy: BusyKind;
  onLoad: (url: string) => void;
  onRefresh: () => void;
  onGoProfiles: () => void;
  onRelaunchAdmin: () => void;
}

export function SubscriptionPanel({ state, busy, onLoad, onRefresh, onGoProfiles, onRelaunchAdmin }: SubscriptionPanelProps) {
  const [url, setUrl] = useState(state.subscriptionUrl);
  const meta = state.subscription;

  const info = [
    { label: "Узлов в подписке", value: String(meta?.nodes ?? 0) },
    { label: "Профилей", value: String(meta?.profiles ?? state.profiles.length) },
    { label: "Пользователь", value: meta?.user || "—" },
    { label: "Загружена", value: meta ? formatDateTime(meta.loadedAt) : "—" },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <section className="card card-pad">
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
          <Link2 size={17} />
          <div>
            <div style={{ fontSize: 15, fontWeight: 800 }}>Ссылка подписки</div>
            <div style={{ fontSize: 12, color: "rgba(238,241,255,.45)" }}>
              JSON с узлами, маршрутами и профилями приходит с сервера Short Polling VPN.
            </div>
          </div>
        </div>
        <div className="field-row">
          <input
            className="input"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && url.trim()) onLoad(url.trim());
            }}
            placeholder="https://fimdi.ru/sub/…"
            spellCheck={false}
            autoComplete="off"
          />
          <button className="btn-load" onClick={() => url.trim() && onLoad(url.trim())} disabled={busy === "subscription" || !url.trim()}>
            {busy === "subscription" ? <Loader2 size={15} /> : <Globe size={15} />}
            {busy === "subscription" ? "Загрузка…" : "Загрузить"}
          </button>
          <button className="btn" onClick={onRefresh} disabled={busy !== null}>
            <RefreshCw size={14} />
            Обновить
          </button>
        </div>
      </section>

      <section className="card card-pad">
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
          <Users size={17} />
          <div style={{ fontSize: 15, fontWeight: 800 }}>Текущая подписка</div>
        </div>
        <div className="stat-grid">
          {info.map((item) => (
            <div className="stat" key={item.label}>
              <div className="stat-label">{item.label}</div>
              <div className="stat-value" style={{ fontSize: 15 }}>
                {item.value}
              </div>
            </div>
          ))}
        </div>
        <div style={{ marginTop: 16, display: "flex", gap: 10, flexWrap: "wrap" }}>
          <button className="btn" onClick={onGoProfiles}>
            Открыть профили
          </button>
        </div>
      </section>

      <section className="card card-pad">
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
          <ShieldAlert size={17} />
          <div style={{ fontSize: 15, fontWeight: 800 }}>Режимы и права</div>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 10 }}>
          <div className="feature">
            <b>Системный прокси</b>
            Приложение сохраняет прежние настройки Windows и восстанавливает их при отключении.
            Локальные адреса не идут через прокси.
          </div>
          <div className="feature">
            <b>TUN-режим</b>
            sing-box поднимает адаптер custom-tun и ведёт через него весь трафик. Требуются права
            администратора.
          </div>
          <div className="feature">
            <b>Права сейчас</b>
            {state.admin ? (
              "Приложение запущено от имени администратора — TUN доступен."
            ) : (
              <>
                TUN недоступен.{" "}
                <button
                  onClick={onRelaunchAdmin}
                  style={{ color: "#b3bdff", background: "none", border: 0, padding: 0, fontWeight: 700 }}
                >
                  Перезапустить от администратора
                </button>
                .
              </>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}
