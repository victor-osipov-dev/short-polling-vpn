import { Power, RefreshCw, ScrollText, ShieldCheck, SlidersHorizontal, Terminal } from "lucide-react";
import type { LogEntry } from "../types";
import { formatClock } from "../lib/format";
import { useState } from "react";

export type LogFilter = "ALL" | "INFO" | "WARNING" | "ERROR";

interface LogViewProps {
  logs: LogEntry[];
  height?: string;
}

export function LogView({ logs, height }: LogViewProps) {
  const [filter, setFilter] = useState<LogFilter>("ALL");
  const [follow, setFollow] = useState(true);

  const filtered = filter === "ALL" ? logs : logs.filter((line) => line.level === filter);

  const onToggle = (value: LogFilter) => {
    setFilter(value);
    setFollow(true);
  };

  return (
    <div className="card logs-tab" style={height ? { height } : undefined}>
      <div className="logs-head">
        <div className="logs-title">
          <Terminal size={15} />
          Журнал событий
        </div>
        <div className="logs-filters">
          {(["ALL", "INFO", "WARNING", "ERROR"] as LogFilter[]).map((value) => (
            <button
              key={value}
              className={`logs-filter ${filter === value ? "active" : ""}`}
              onClick={() => onToggle(value)}
            >
              {value === "ALL" ? "Все" : value === "INFO" ? "Инфо" : value === "WARNING" ? "Пред." : "Ошибки"}
            </button>
          ))}
          <button className="logs-filter" onClick={() => setFollow((v) => !v)}>
            {follow ? "Следить" : "Стою"}
          </button>
        </div>
      </div>
      <div
        className="logs-body"
        ref={(node) => {
          if (node && follow) node.scrollTop = node.scrollHeight;
        }}
      >
        {filtered.length === 0 ? (
          <div className="logs-empty">Событий пока нет</div>
        ) : (
          filtered.map((line, index) => (
            <div className="log-line" key={`${line.t}-${index}`}>
              <span className="log-time">{formatClock(line.t)}</span>
              <span className={`log-level ${line.level}`}>{line.level}</span>
              <span className="log-msg">{line.message}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
