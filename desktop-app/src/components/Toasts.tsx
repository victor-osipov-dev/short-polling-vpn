import { CheckCircle2, Info, X, XCircle } from "lucide-react";
import type { Toast } from "../hooks/useVpn";

interface ToastsProps {
  toasts: Toast[];
  onDismiss: (id: number) => void;
}

export function Toasts({ toasts, onDismiss }: ToastsProps) {
  return (
    <div className="toasts">
      {toasts.map((toast) => (
        <div className={`toast ${toast.kind}`} key={toast.id}>
          {toast.kind === "success" && <CheckCircle2 size={17} />}
          {toast.kind === "error" && <XCircle size={17} />}
          {toast.kind === "info" && <Info size={17} />}
          <span className="grow">{toast.message}</span>
          <button className="toast-close" onClick={() => onDismiss(toast.id)} aria-label="Закрыть">
            <X size={15} />
          </button>
        </div>
      ))}
    </div>
  );
}
