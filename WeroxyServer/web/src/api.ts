export class ApiError extends Error {
  code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

export type Revision = { desired_revision: number; applied_revision: number; failure_reason: string; updated_at: string };
const revisionCache = new Map<string, number>();
const pendingOperations = new Map<string, { id: string; revision: number }>();
let cacheGeneration = 0;
function resetConfigurationCache() {
  cacheGeneration++;
  revisionCache.clear();
  pendingOperations.clear();
}

function absorbRevisions(body: unknown) {
  if (!body || typeof body !== "object") return;
  const data = body as Record<string, unknown>;
  if (data.revisions && typeof data.revisions === "object") {
    for (const [domain, value] of Object.entries(data.revisions as Record<string, Revision>)) {
      if (Number.isSafeInteger(value?.desired_revision)) revisionCache.set(domain, value.desired_revision);
    }
  }
  if (typeof data.domain === "string" && Number.isSafeInteger(data.desired_revision)) {
    revisionCache.set(data.domain, data.desired_revision as number);
  }
}

function mutationDomain(path: string, method: string): string | null {
  if (method === "PUT" && path === "/api/v1/settings") return "ui";
  if(method === "PUT" && path === "/api/v1/firewall/sync") return "policy";
  if (method === "POST" && (path === "/api/v1/policy" || path === "/api/v1/bans" || path === "/api/v1/bans/delete")) return "policy";
  if (method === "POST" && (path === "/api/v1/forwards" || path === "/api/v1/forwards/delete" || path === "/api/v1/forwards/enabled" || path === "/api/v1/forwards/shrink")) return "listener";
  if (method === "POST" && (path === "/api/v1/devices" || path === "/api/v1/devices/rename" || path === "/api/v1/devices/key" || path === "/api/v1/devices/protocol" || path === "/api/v1/devices/paused" || path === "/api/v1/devices/delete" || path === "/api/v1/devices/revoke")) return "credential";
  return null;
}

function operationDigest(body: BodyInit | null | undefined): string {
  // This is only a bounded in-memory retry key. The server hashes requests.
  return typeof body === "string" ? body : "";
}

function operationID(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

// Keep the deadline active through response body reads, then release all listeners.
async function requestJSON(path: string, init: RequestInit = {}): Promise<{ res: Response; body: any }> {
  const controller = new AbortController();
  let timedOut = false;
  const cancel = () => controller.abort();
  if (init.signal?.aborted) cancel();
  else init.signal?.addEventListener("abort", cancel, { once: true });
  const timer = window.setTimeout(() => { timedOut = true; controller.abort(); }, path.startsWith("/api/v1/backup") ? 150000 : 15000);
  try {
    const res = await fetch(path, { ...init, credentials: "include", signal: controller.signal });
    const text = await res.text();
    return { res, body: text ? JSON.parse(text) : {} };
  } catch (error) {
    if (timedOut) throw new ApiError("request_timeout");
    throw error;
  } finally {
    window.clearTimeout(timer);
    init.signal?.removeEventListener("abort", cancel);
  }
}

async function ensureRevision(domain: string) {
  const generation = cacheGeneration;
  if (revisionCache.has(domain)) return;
  const { res, body } = await requestJSON("/api/v1/config/revisions");
  if (generation !== cacheGeneration) throw new ApiError("session_changed");
  if (!res.ok) throw new ApiError(typeof body.error === "string" ? body.error : "invalid");
  absorbRevisions(body);
  if (!revisionCache.has(domain)) throw new ApiError("invalid");
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const generation = cacheGeneration;
  const headers = new Headers(init.headers);
  if (init.body && !(init.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const domain = mutationDomain(path, (init.method || "GET").toUpperCase());
  if (domain) {
    await ensureRevision(domain);
    headers.set("X-Expected-Revision", String(revisionCache.get(domain)));
  }
  const sensitive = domain !== null && path !== "/api/v1/settings";
  const operationKey = sensitive ? `${init.method || "GET"}:${path}:${operationDigest(init.body)}` : "";
  if (generation !== cacheGeneration) throw new ApiError("session_changed");
  if (sensitive) {
    let operation = pendingOperations.get(operationKey);
    if (!operation) {
      if (pendingOperations.size >= 64) throw new ApiError("pending_operation_capacity");
      operation = { id: operationID(), revision: revisionCache.get(domain!)! };
      pendingOperations.set(operationKey, operation);
    }
    headers.set("Idempotency-Key", operation.id);
    headers.set("X-Expected-Revision", String(operation.revision));
  }
  const { res, body } = await requestJSON(path, { ...init, headers });
  if (generation !== cacheGeneration) throw new ApiError("session_changed");
  if (!res.ok) {
    if (res.status === 401) resetConfigurationCache();
    if (res.status === 409 && domain) {
      revisionCache.delete(domain);
      if (sensitive) pendingOperations.delete(operationKey);
    }
    if (sensitive && res.status >= 400 && res.status < 500) pendingOperations.delete(operationKey);
    throw new ApiError(typeof body.error === "string" ? body.error : "invalid");
  }
  if ((path === "/api/v1/auth/sessions/revoke" && body.current === true) || ["/api/v1/auth/login", "/api/v1/auth/logout", "/api/v1/auth/password", "/api/v1/backup/upload"].includes(path) && (init.method || "GET").toUpperCase() === "POST") {
    resetConfigurationCache();
  } else {
    absorbRevisions(body);
    if (sensitive) pendingOperations.delete(operationKey);
  }
  return body as T;
}

export type Limits = {
  max_pending: number | null;
  max_per_ip: number | null;
  rate: number | null;
  burst: number | null;
  idle_sec?: number | null;
  connect_sec?: number | null;
  wait_sec?: number | null;
  bandwidth?: number | null;
};

export type Forward = {
  up_bytes?: number;
  down_bytes?: number;
  data_ports?: number[];
  publication_status?: string;
  device_reachability?: string;
  runtime_known?: boolean;
  data_current?: number;
  data_healthy?: number;
  data_draining?: number;
  available_max?: number;
  can_grow?: number;
  limiting_reasons?: string[];
  manual_data_ports?: number[];
  listen: string;
  target: string;
  mode: string;
  min?: number;
  preferred?: number;
  max?: number;
  enabled?: boolean;
  effective?: Limits;
};

export type ApplyStatus = "saved" | "applying" | "applied" | "failed";

export type Preview = {
  ok: boolean;
  error: string;
  conflict_role: string;
  listen: string;
  target: string;
  protocol: string;
  mode: string;
  min: number;
  preferred: number;
  max: number;
  timeouts: string;
  apply: ApplyStatus;
  deployment_required?: boolean;
  effective?: Limits;
};

export type Device = {
  data_physical_count?: number;
  data_allocation_count?: number;
  effective?: Limits;
  name: string;
  protocol: "weroxy" | "legacy";
  client_key?: string;
  key_saved: boolean;
  online: boolean;
  online_known?: boolean;
  sessions: number;
  up_bytes: number;
  down_bytes: number;
  forwards: Forward[];
  rules: { scope: string; device: string; listen: string; cidr: string; action: string; expires_at?: string | null; kernel_status?: string; kernel_retry_count?: number; policy_generation?: number }[];
  policies: ({
    scope: string;
    device: string;
    listen: string;
  } & Limits)[];
  revoked: boolean;
  paused?: boolean;
  client_version: string | null;
  control_rtt_ms?: number | null;
  legacy_limits: string[];
};

export type StatusPoint = {
  at: string;
  duration_sec?: number;
  state: "online" | "idle" | "offline";
  sessions: number;
  up_bytes: number;
  down_bytes: number;
};

export type StatusDevice = {
  name: string;
  protocol: string;
  online: boolean;
  online_known?: boolean;
  sessions: number;
  up_bytes: number;
  down_bytes: number;
  forwards: number;
  state: "online" | "idle" | "offline";
  control_rtt_ms?: number | null;
  history: StatusPoint[];
};

export type Connection = {
  id: number;
  protocol: "legacy" | "weroxy";
  session_id: string;
  device_id: number;
  forward_id: number;
  device: string;
  forward_listen: string;
  source_ip: string;
  client_os: string;
  data_port: number;
  started_at: string;
  last_at: string;
  ready_at?: string;
  setup_ms?: number;
  closed_at?: string;
  close_reason?: string;
  up_bytes: number;
  down_bytes: number;
  status: "active" | "closed";
};

export type Dashboard = {
  refresh_sec: number;
  sample_sec: number;
  online_devices: number;
  active_sessions: number;
  forwards: number;
  data_ports: number;
  online_weroxy_devices: number;
  online_legacy_devices: number;
  up_bytes: number;
  down_bytes: number;
  rejected: number;
  failures?: { data_dial_failures?: number; target_dial_failures?: number; target_denials?: number; client_busy?: number };
  series: { at: string; up_bytes: number; down_bytes: number }[];
  traffic_history?: { at: string; up_bytes: number; down_bytes: number; samples: number; gaps: number }[];
  metrics_persistence?: { last_sample_at: string; last_write_at: string; write_delay_ms: number; dropped_batches: number; failure_reason: string };
  connection_persistence?: { queued: number; dropped: number };
  devices: StatusDevice[];
};

export type Publication = {
  status: "unverified" | "stale" | "partial" | "published";
  checked_at?: string;
  listener_count: number;
  published_count: number;
  missing_ports: number[];
  loopback_only: boolean;
};

export type Settings = {
  locale: "zh" | "en";
  theme: "system" | "light" | "dark";
  pool: {
    enabled: boolean;
    forward_first: number;
    unavailable_forward?: number[];
    forward_last: number;
    data_first: number;
    data_last: number;
    bind_host: string;
  };
  publication: Publication;
  defaults: {
    mode: string;
    min: number;
    preferred: number;
    max: number;
    limits: {
      max_pending: number | null;
      max_per_ip: number | null;
      rate: number | null;
      burst: number | null;
      idle_sec: number | null;
      connect_sec: number | null;
      wait_sec: number | null;
      bandwidth: number | null;
      status: string;
    };
  };

};
