import { useCallback, useEffect, useRef, useState } from "react";
import type { LogEntry, Mode, Profile, VpnState } from "../types";

export type ToastKind = "success" | "error" | "info";

export interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
}

export type BusyKind = "boot" | "subscription" | "connect" | "disconnect" | null;

function cleanError(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error ?? "");
  return raw
    .replace(/^Error invoking remote method '[^']+':\s*/i, "")
    .replace(/^Error:\s*/i, "")
    .trim();
}

export function useVpn() {
  const [state, setState] = useState<VpnState | null>(null);
  const [busy, setBusy] = useState<BusyKind>("boot");
  const [bootError, setBootError] = useState<string | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const counter = useRef(0);
  const stateRef = useRef<VpnState | null>(null);

  const pushToast = useCallback((kind: ToastKind, message: string) => {
    const id = ++counter.current;
    setToasts((prev) => [...prev.slice(-3), { id, kind, message }]);
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, kind === "error" ? 7000 : 4000);
  }, []);

  const dismissToast = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const refresh = useCallback(async (quiet = true) => {
    try {
      const next = await window.fimdi.getState();
      stateRef.current = next;
      setState(next);
      setBootError(null);
      return next;
    } catch (error) {
      if (!quiet) pushToast("error", cleanError(error));
      return null;
    }
  }, [pushToast]);

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;

    const tick = async () => {
      if (cancelled) return;
      try {
        const next = await window.fimdi.getState();
        if (!cancelled) {
          stateRef.current = next;
          setState(next);
          setBootError(null);
          setBusy((current) => (current === "boot" ? null : current));
        }
      } catch (error) {
        if (!cancelled) {
          const message = cleanError(error);
          setBootError(message);
          setBusy((current) => (current === "boot" ? null : current));
        }
      } finally {
        if (!cancelled) timer = window.setTimeout(tick, 900);
      }
    };

    tick();
    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  }, []);

  const loadSubscription = useCallback(
    async (url: string) => {
      setBusy("subscription");
      try {
        const res = await window.fimdi.loadSubscription(url);
        setState(res.state);
        stateRef.current = res.state;
        pushToast("success", `Подписка загружена: ${res.state.profiles.length} профилей`);
        return res.state;
      } catch (error) {
        pushToast("error", cleanError(error));
        await refresh();
        return null;
      } finally {
        setBusy(null);
      }
    },
    [pushToast, refresh],
  );

  const connect = useCallback(
    async (profileId: string, mode: Mode, global: boolean) => {
      setBusy("connect");
      try {
        const res = await window.fimdi.connect({ profileId, mode, global });
        setState(res.state);
        stateRef.current = res.state;
        if (res.state.phase === "error") {
          pushToast("error", res.state.error || "Не удалось подключиться");
        } else {
          pushToast("success", `Подключено: ${res.state.profile?.name ?? "профиль"}`);
        }
        return res.state;
      } catch (error) {
        pushToast("error", cleanError(error));
        await refresh();
        return null;
      } finally {
        setBusy(null);
      }
    },
    [pushToast, refresh],
  );

  const disconnect = useCallback(async () => {
    setBusy("disconnect");
    try {
      const res = await window.fimdi.disconnect();
      setState(res.state);
      stateRef.current = res.state;
      pushToast("info", "Соединение закрыто");
      return res.state;
    } catch (error) {
      pushToast("error", cleanError(error));
      await refresh();
      return null;
    } finally {
      setBusy(null);
    }
  }, [pushToast, refresh]);

  const recheck = useCallback(async () => {
    try {
      const res = await window.fimdi.recheck();
      setState(res.state);
      stateRef.current = res.state;
      pushToast("info", "Проверяем внешний IP…");
    } catch (error) {
      pushToast("error", cleanError(error));
    }
  }, [pushToast]);

  const relaunchAdmin = useCallback(async () => {
    try {
      await window.fimdi.relaunchAdmin();
    } catch (error) {
      pushToast("error", cleanError(error));
    }
  }, [pushToast]);

  const selectProfile = useCallback(
    async (profile: Profile) => {
      const current = stateRef.current;
      if (!current) return;
      if (current.connected && current.profileId !== profile.id) {
        await connect(profile.id, current.mode, current.global);
        return;
      }
      setState((prev) => (prev ? { ...prev, profileId: profile.id, profile } : prev));
    },
    [connect],
  );

  return {
    state,
    busy,
    bootError,
    toasts,
    refresh,
    loadSubscription,
    connect,
    disconnect,
    recheck,
    relaunchAdmin,
    selectProfile,
    pushToast,
    dismissToast,
    logs: (state?.logs ?? []) as LogEntry[],
  };
}
