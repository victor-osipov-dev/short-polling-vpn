import { useCallback, useEffect, useMemo, useState } from "react";
import { RefreshCw, Terminal, X } from "lucide-react";
import { useVpn } from "./hooks/useVpn";
import type { Mode, Profile } from "./types";
import { Sidebar, type Tab } from "./components/Sidebar";
import { SetupPanel } from "./components/SetupPanel";
import { SubscriptionStrip } from "./components/SubscriptionStrip";
import { ConnectPanel } from "./components/ConnectPanel";
import { ProfilesSection } from "./components/ProfilesSection";
import { SubscriptionPanel } from "./components/SubscriptionPanel";
import { LogView } from "./components/LogView";
import { Toasts } from "./components/Toasts";

const TITLES: Record<Tab, { title: string; sub: string }> = {
  vpn: {
    title: "Подключение",
    sub: "Профиль, режим и состояние туннеля",
  },
  subscription: {
    title: "Подписка",
    sub: "Источник узлов, маршрутов и профилей",
  },
  logs: {
    title: "Журнал",
    sub: "События клиента, прокси и sing-box",
  },
};

export default function App() {
  const vpn = useVpn();
  const { state, busy, bootError, toasts, dismissToast } = vpn;
  const [tab, setTab] = useState<Tab>("vpn");
  const [logsOpen, setLogsOpen] = useState(false);
  const [modePref, setModePref] = useState<Mode>("proxy");
  const [globalPref, setGlobalPref] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [dismissedError, setDismissedError] = useState<string | null>(null);

  useEffect(() => {
    if (state?.error && state.error !== dismissedError) setDismissedError(null);
  }, [state?.error]);

  useEffect(() => {
    if (state) {
      setModePref(state.mode);
      setGlobalPref(state.global);
    }
  }, [state?.mode, state?.global]);

  useEffect(() => {
    if (state?.profileId) setSelectedId(state.profileId);
  }, [state?.profileId]);

  const selectedProfile = useMemo(() => {
    if (!state) return null;
    return state.profiles.find((profile) => profile.id === selectedId) ?? state.profile ?? state.profiles[0] ?? null;
  }, [state, selectedId]);

  const connectedProfileId = state?.connected ? state.profileId : null;

  const handleModeChange = useCallback(
    async (mode: Mode) => {
      setModePref(mode);
      if (!state?.connected || !selectedProfile) return;
      if (mode === "tun" && !state.admin) {
        vpn.pushToast("info", "Для TUN нужны права администратора. Перезапустите приложение от администратора.");
        return;
      }
      await vpn.connect(selectedProfile.id, mode, globalPref);
    },
    [state?.connected, state?.admin, selectedProfile, globalPref, vpn],
  );

  const handleGlobalChange = useCallback(
    async (value: boolean) => {
      setGlobalPref(value);
      if (!state?.connected || !selectedProfile) return;
      await vpn.connect(selectedProfile.id, modePref, value);
    },
    [state?.connected, selectedProfile, modePref, vpn],
  );

  const handleToggle = useCallback(async () => {
    if (!state || !selectedProfile) return;
    if (state.connected) {
      await vpn.disconnect();
      return;
    }
    if (busy) return;
    if (modePref === "tun" && !state.admin) {
      vpn.pushToast("info", "Для TUN нужны права администратора. Используйте системный прокси или перезапустите приложение.");
      return;
    }
    await vpn.connect(selectedProfile.id, modePref, globalPref);
  }, [state, selectedProfile, busy, modePref, globalPref, vpn]);

  const handleSelectProfile = useCallback(
    async (profile: Profile) => {
      setSelectedId(profile.id);
      if (!state?.connected || state.profileId === profile.id) return;
      await vpn.connect(profile.id, state.mode, state.global);
    },
    [state, vpn],
  );

  const handleRefreshSubscription = useCallback(async () => {
    if (!state) return;
    const url = state.subscription?.url ?? state.subscriptionUrl;
    if (url) await vpn.loadSubscription(url);
    else await vpn.refresh();
  }, [state, vpn]);

  const handleCopy = useCallback(
    async (value: string) => {
      try {
        await navigator.clipboard.writeText(value);
        vpn.pushToast("success", `Скопировано: ${value}`);
      } catch {
        vpn.pushToast("error", "Не удалось скопировать в буфер обмена");
      }
    },
    [vpn],
  );

  if (!state) {
    return (
      <div className="boot">
        <div className="boot-mark">
          <Terminal size={30} />
        </div>
        <div className="spinner" />
        <div className="boot-text">Запускаем службу VPN…</div>
        {bootError && <div className="boot-error">{bootError}</div>}
      </div>
    );
  }

  const titles = TITLES[tab];

  return (
    <div className="app-shell">
      <div className="titlebar">
        <div className="titlebar-brand">
          <span className="titlebar-dot" />
          FIMDI VPN
        </div>
      </div>

      <Sidebar
        state={state}
        tab={tab}
        onTab={setTab}
        onRefresh={() => vpn.refresh()}
        busy={busy}
      />

      <main className="main">
        <div className="topbar">
          <div>
            <div className="page-title">{titles.title}</div>
            <div className="page-sub">{titles.sub}</div>
          </div>
          <div className="topbar-actions">
            {tab !== "logs" && (
              <button className="icon-btn" onClick={handleRefreshSubscription} disabled={busy !== null || !state.subscription}>
                <RefreshCw size={15} className={busy === "subscription" ? "animate-spin" : undefined} />
                <span className="nav-label">
                  {busy === "subscription" ? "Загрузка…" : "Обновить подписку"}
                </span>
              </button>
            )}
            <button className="icon-btn" onClick={() => setLogsOpen(true)} disabled={tab === "logs"}>
              <Terminal size={15} />
              <span className="nav-label">Журнал</span>
            </button>
          </div>
        </div>

        {state.error && state.error !== dismissedError && (
          <div className="error-banner">
            <span>⚠️</span>
            <span className="grow">{state.error}</span>
            <button className="btn ghost" onClick={() => setDismissedError(state.error)}>
              Скрыть
            </button>
          </div>
        )}

        {tab === "vpn" &&
          (state.profiles.length === 0 ? (
            <SetupPanel initialUrl={state.subscriptionUrl} busy={busy} onLoad={vpn.loadSubscription} />
          ) : (
            <>
              {state.subscription && (
                <SubscriptionStrip state={state} busy={busy} onRefresh={handleRefreshSubscription} />
              )}
              <ConnectPanel
                state={state}
                busy={busy}
                mode={modePref}
                global={globalPref}
                onModeChange={handleModeChange}
                onGlobalChange={handleGlobalChange}
                onToggle={handleToggle}
                onRecheck={vpn.recheck}
                onRelaunchAdmin={vpn.relaunchAdmin}
                onCopy={handleCopy}
              />
              <ProfilesSection
                state={state}
                selectedId={selectedProfile?.id ?? null}
                connectedProfileId={connectedProfileId}
                busy={busy}
                onSelect={handleSelectProfile}
              />
            </>
          ))}

        {tab === "subscription" && (
          <SubscriptionPanel
            state={state}
            busy={busy}
            onLoad={vpn.loadSubscription}
            onRefresh={handleRefreshSubscription}
            onGoProfiles={() => setTab("vpn")}
            onRelaunchAdmin={vpn.relaunchAdmin}
          />
        )}

        {tab === "logs" && <LogView logs={vpn.logs} height="calc(100vh - 170px)" />}
      </main>

      <div className={`logs-panel ${logsOpen ? "open" : ""}`}>
        <button
          className="icon-btn"
          onClick={() => setLogsOpen(false)}
          style={{ position: "absolute", right: 12, top: 10, zIndex: 2 }}
          aria-label="Закрыть журнал"
        >
          <X size={15} />
        </button>
        <LogView logs={vpn.logs} />
      </div>

      <Toasts toasts={toasts} onDismiss={dismissToast} />
    </div>
  );
}
