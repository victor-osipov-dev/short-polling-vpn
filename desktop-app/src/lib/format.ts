export function formatUptime(seconds: number): string {
  if (!seconds || seconds < 0) return "0:00";
  const total = Math.floor(seconds);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  const pad = (value: number) => String(value).padStart(2, "0");
  if (hours > 0) return `${hours}:${pad(minutes)}:${pad(secs)}`;
  return `${minutes}:${pad(secs)}`;
}

export function formatBytes(bytes: number): string {
  if (!bytes || bytes < 0) return "0 Б";
  const units = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  if (unit === 0) return `${Math.round(value)} ${units[unit]}`;
  return `${value.toFixed(value >= 100 ? 0 : value >= 10 ? 1 : 2)} ${units[unit]}`;
}

export function formatClock(timestamp: number): string {
  if (!timestamp) return "—";
  const date = new Date(timestamp * 1000);
  return date.toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function formatDateTime(timestamp: number): string {
  if (!timestamp) return "—";
  const date = new Date(timestamp * 1000);
  return date.toLocaleString("ru-RU", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export const PHASE_LABEL: Record<string, string> = {
  idle: "Готово к подключению",
  connecting: "Подключение…",
  connected: "Защищено",
  disconnecting: "Отключение…",
  error: "Ошибка подключения",
};

export const PHASE_SHORT: Record<string, string> = {
  idle: "Не подключено",
  connecting: "Подключение",
  connected: "Защищено",
  disconnecting: "Отключение",
  error: "Ошибка",
};
