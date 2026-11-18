import { CheckCircle2, RefreshCw, Users } from "lucide-react";
import type { VpnState } from "../types";
import { formatDateTime } from "../lib/format";

interface SubscriptionStripProps {
  state: VpnState;
  busy: string | null;
  onRefresh: () => void;
}

export function SubscriptionStrip({ state, busy, onRefresh }: SubscriptionStripProps) {
  const meta = state.subscription;
  return (
    <div className="sub-strip">
      <CheckCircle2 size={20} style={{ color: "#3ee6a8", flex: "0 0 auto" }} />
      <div className="grow">
        <div className="sub-title">
          Подписка активна
          <span className="chip mint">
            <Users size={12} />
            {meta?.user || "пользователь"}
          </span>
        </div>
        <div className="sub-url" title={meta?.url ?? state.subscriptionUrl}>
          {meta?.url ?? state.subscriptionUrl}
        </div>
      </div>
      <div className="sub-stats">
        <span className="chip indigo">{meta?.nodes ?? 0} узлов</span>
        <span className="chip indigo">{meta?.profiles ?? state.profiles.length} профилей</span>
        <span className="chip">{meta ? formatDateTime(meta.loadedAt) : "—"}</span>
      </div>
      <button className="icon-btn" onClick={onRefresh} disabled={busy !== null} title="Обновить подписку">
        <RefreshCw size={15} className={busy === "subscription" ? "animate-spin" : undefined} />
        <span className="nav-label">Обновить</span>
      </button>
    </div>
  );
}
