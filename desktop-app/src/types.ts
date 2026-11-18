export type Phase =
  | "idle"
  | "connecting"
  | "connected"
  | "disconnecting"
  | "error";

export type Mode = "proxy" | "tun";

export interface RouteInfo {
  kind: "direct" | "route";
  route: string;
  label: string;
  chain: string[];
}

export interface Profile {
  id: string;
  name: string;
  sortOrder: number;
  region: string;
  regionName: string;
  flag: string;
  color: string;
  tags: string[];
  split: boolean;
  mode: string;
  ru: RouteInfo;
  nonRu: RouteInfo;
  private: RouteInfo;
  primaryLabel: string;
  chain: string[];
  nodeId?: string;
  nodeUrl?: string;
}

export interface ExitInfo {
  ip?: string | null;
  countryCode?: string;
  city?: string;
  org?: string;
  checkedAt?: number;
  error?: string;
}

export interface SubscriptionMeta {
  url: string;
  loadedAt: number;
  nodes: number;
  profiles: number;
  user: string;
}

export interface LogEntry {
  t: number;
  level: "INFO" | "WARNING" | "ERROR" | "DEBUG" | string;
  message: string;
  source?: string;
}

export interface VpnState {
  version: string;
  phase: Phase;
  mode: Mode;
  connected: boolean;
  profileId: string | null;
  profile: Profile | null;
  profiles: Profile[];
  subscription: SubscriptionMeta | null;
  subscriptionUrl: string;
  global: boolean;
  error: string | null;
  exit: ExitInfo | null;
  admin: boolean;
  ports: { socks: number; http: number; api: number };
  proxy: { active: boolean; host: string; port: number };
  tun: { available: boolean; running: boolean; error: string | null };
  stats: {
    uptime: number;
    sessions: number;
    polls: number;
    up: number;
    down: number;
  };
  logs: LogEntry[];
}

export interface FimdiApi {
  getState(): Promise<VpnState>;
  getLogs(): Promise<{ logs: LogEntry[] }>;
  loadSubscription(url: string): Promise<{ ok: boolean; state: VpnState }>;
  connect(payload: {
    profileId: string;
    mode: Mode;
    global: boolean;
  }): Promise<{ ok: boolean; state: VpnState }>;
  disconnect(): Promise<{ ok: boolean; state: VpnState }>;
  recheck(): Promise<{ ok: boolean; state: VpnState }>;
  appInfo(): Promise<{ version: string; platform: string; dev: boolean; packaged: boolean }>;
  relaunchAdmin(): Promise<{ ok: boolean }>;
  openExternal(url: string): Promise<void>;
}

declare global {
  interface Window {
    fimdi: FimdiApi;
  }
}
