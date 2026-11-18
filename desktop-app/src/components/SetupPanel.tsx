import { useState } from "react";
import { Globe, Link2, Loader2, Route, ShieldCheck } from "lucide-react";

interface SetupPanelProps {
  initialUrl: string;
  busy: string | null;
  onLoad: (url: string) => void;
}

export function SetupPanel({ initialUrl, busy, onLoad }: SetupPanelProps) {
  const [url, setUrl] = useState(initialUrl);

  const submit = () => {
    if (!url.trim()) return;
    onLoad(url.trim());
  };

  return (
    <div className="setup-wrap">
      <div className="card setup-card">
        <div className="setup-badge">
          <ShieldCheck size={30} strokeWidth={2.4} />
        </div>
        <h1 className="setup-title">Подключите свою подписку</h1>
        <p className="setup-text">
          Вставьте ссылку, которую выдал FIMDI VPN. Приложение загрузит список узлов и профилей,
          выберите подходящий маршрут и включите системный прокси или полноценный VPN в режиме TUN.
        </p>

        <div className="field-row">
          <div className="search" style={{ flex: 1 }}>
            <Link2 size={15} />
            <input
              className="input"
              style={{ paddingLeft: 34 }}
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") submit();
              }}
              placeholder="https://fimdi.ru/sub/…"
              spellCheck={false}
              autoComplete="off"
            />
          </div>
          <button className="btn-load" onClick={submit} disabled={busy === "subscription" || !url.trim()}>
            {busy === "subscription" ? <Loader2 size={15} className="animate-spin" /> : <Globe size={15} />}
            {busy === "subscription" ? "Загружаем…" : "Загрузить"}
          </button>
        </div>

        <div className="setup-features">
          <div className="feature">
            <b>Профили маршрутов</b>
            Россия, СНГ, Европа и Азия — для каждого профиля задано, какие домены идут напрямую,
            а какие через выход.
          </div>
          <div className="feature">
            <b>Системный прокси</b>
            Приложения, которые уважают настройки Windows, включая браузеры и мессенджеры,
            подхватят прокси автоматически.
          </div>
          <div className="feature">
            <b>Режим TUN</b>
            Для остальных приложений — настоящий VPN-адаптер через sing-box. Требует прав
            администратора.
          </div>
        </div>
      </div>
    </div>
  );
}
