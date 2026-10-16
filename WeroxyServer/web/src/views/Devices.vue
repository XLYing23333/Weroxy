<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { useI18n } from "vue-i18n";
import { ApiError, api, type ApplyStatus, type Device, type Forward, type Preview, type Settings, type Connection } from "../api";
import { formatBytes, formatCount as compact } from "../format";
import { filters } from "../filters";
import { reasonText } from "../i18n";
import ForwardForm from "../ForwardForm.vue";
import { policyFields } from "../policyFields";
import IconButton from "../IconButton.vue";
import { notify, type NoticeTone } from "../notice";
import { refreshTick, refreshViews } from "../refresh";
import { usePoll } from "../poll";

const route = useRoute();
const router = useRouter();
const { t } = useI18n();
const devices = ref<Device[]>([]);
const bindHost = ref("127.0.0.1");
const productDefaults = ref<Settings["defaults"] | null>(null);
const defaultsReady = ref(false);
const poolEnabled = ref(true);
const poolFirst = ref(29000);
const poolLast = ref(29099);
const hostOccupied = ref<number[]>([]);
const error = ref("");
const adding = ref(false);
const notice = ref("");
const preview = ref<Preview | null>(null);
const previewKey = ref("");
const listLimit = ref(16);
const forwardLimit = ref(16);
const visitorLimit = ref(16);
const banLimit = ref(16);
const deviceTable = ref<{ $el?: HTMLElement } | null>(null);
const forwardTable = ref<{ $el?: HTMLElement } | null>(null);
type SelectionTable = { $el?: HTMLElement; clearSelection: () => void; toggleRowSelection: (row: unknown, selected: boolean) => void };
const visitorTable = ref<SelectionTable | null>(null);
const banTable = ref<SelectionTable | null>(null);
const pickedVisitors = ref<{ ip: string; active: boolean }[]>([]);
const pickedBans = ref<Device["rules"][number][]>([]);
const banRowKey = (row: Device["rules"][number]) => `${row.scope}:${row.listen || ""}:${row.cidr}`;
const savedKeys = new Map<string, string>();
const sortProp = ref("protocol");
const sortOrder = ref<"ascending" | "descending" | null>("ascending");
const ask = ref<{ title: string; detail: string; run: () => Promise<void> } | null>(null);
const form = reactive({
  name: "",
  protocol: "weroxy",
  clientKey: "",
  port: "29010",
  target: "127.0.0.1:8080",
  mode: "shared",
  min: 1,
  preferred: 1,
  max: 1,
  idle: "",
  connect: "",
  wait: "",
  bandwidth: "",
});
const visitorNext = ref("");
const visitorCursor=ref("");
const visitorPrevious=ref<string[]>([]);
const visitors = ref<{ ip: string; os: string; active: boolean; active_connections: number; connections: number; bytes: number; last_unix: number }[]>([]);
const detailTab = ref("ports");
const actionBusy = ref(false);
const previewBusy = ref(false);
const connectionRows = ref<Connection[]>([]);
const connectionNext = ref(0);
const connectionLoading = ref(false);
const connectionError = ref("");


const selected = computed(() => devices.value.find((item) => item.name === route.params.name));
const shown = computed(() =>
  devices.value.filter((item) => {
    const name = filters.q.trim().toLowerCase();
    if (name && !item.name.toLowerCase().includes(name)) return false;
    if (filters.protocol !== "all" && item.protocol !== filters.protocol) return false;
    return true;
  }),
);
const ranked = computed(() => {
  const rows = [...shown.value];
  const dir = sortOrder.value === "descending" ? -1 : 1;
  const prop = sortProp.value;
  rows.sort((a, b) => dir * compare(a, b, prop));
  return rows;
});
const paged = computed(() => ranked.value.slice(0, listLimit.value));
const shownForwards = computed(() => (selected.value?.forwards ?? []).slice(0, forwardLimit.value));
function bannedIP(ip: string) {
  const rules = selected.value?.rules.filter((rule) => rule.action === "ban") ?? [];
  const dotted = ip.split(".").map(Number);
  for (const rule of rules) {
    const [network, widthText] = rule.cidr.split("/");
    if (network === ip) return true;
    const width = Number(widthText);
    const octets = network.split(".").map(Number);
    if (dotted.length === 4 && octets.length === 4 && Number.isInteger(width) && width >= 0 && width <= 32 &&
      [...dotted, ...octets].every((part) => Number.isInteger(part) && part >= 0 && part <= 255)) {
      const mask = width === 0 ? 0 : (0xffffffff << (32 - width)) >>> 0;
      const address = dotted.reduce((value, part) => ((value << 8) | part) >>> 0, 0);
      const base = octets.reduce((value, part) => ((value << 8) | part) >>> 0, 0);
      if ((address & mask) === (base & mask)) return true;
    }
    if ((width === 128 || width === 32) && network === ip) return true;
  }
  return false;
}
const visibleVisitors = computed(() => visitors.value.filter((row) => !bannedIP(row.ip)));
const shownVisitors = computed(() => visibleVisitors.value.slice(0, visitorLimit.value));
const shownBans = computed(() => (selected.value?.rules.filter((rule) => rule.action === "ban") ?? []).slice(0, banLimit.value));
const freshPreview = computed(() => preview.value !== null && previewKey.value === forwardKey());
const usedPorts = computed(() => {
  const ports = new Set<number>();
  for (const device of devices.value) {
    for (const row of device.forwards) ports.add(Number(portOf(row.listen)));
  }
  return ports;
});
const editingListen = ref("");
const editOpen=ref(false);
const editDraft=reactive({...form});
let createDraft:typeof form|null=null;
const portTaken = computed(() => {
  const port = Number(form.port);
  if (editingListen.value && Number(portOf(editingListen.value)) === port) return false;
  return usedPorts.value.has(port) || hostOccupied.value.includes(port);
});
const freePortCount = computed(() => {
  if (!poolEnabled.value) return 0;
  const size = Math.max(0, poolLast.value - poolFirst.value + 1);
  const occupied = new Set([...usedPorts.value, ...hostOccupied.value].filter(port => port >= poolFirst.value && port <= poolLast.value)).size;
  return Math.max(0, size - occupied);
});
const availablePorts = computed(() => {
  if (!poolEnabled.value) return [];
  const result: string[] = [];
  for (let port = poolFirst.value; port <= poolLast.value && result.length < 200; port++) {
    if ((!usedPorts.value.has(port) && !hostOccupied.value.includes(port)) || (editingListen.value && Number(portOf(editingListen.value)) === port)) result.push(String(port));
  }
  if (editingListen.value) {
    const current = portOf(editingListen.value);
    if (!result.includes(current)) result.unshift(current);
  }
  return result;
});
const portValid = computed(() => {
  if (!/^\d+$/.test(form.port)) return false;
  const port = Number(form.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535 || portTaken.value) return false;
  return !poolEnabled.value || (port >= poolFirst.value && port <= poolLast.value) ||
    (editingListen.value !== "" && port === Number(portOf(editingListen.value)));
});
const portHint = computed(() => {
  if (!poolEnabled.value) return t("portManualHint");
  if (!editingListen.value && freePortCount.value === 0) return t("portPoolFull", { first: poolFirst.value, last: poolLast.value });
  if (!portValid.value && form.port) return t("portInvalidHint", { first: poolFirst.value, last: poolLast.value });
  return t(freePortCount.value > 200 ? "portPoolManyHint" : "portPoolHint", { first: poolFirst.value, last: poolLast.value, count: freePortCount.value });
});
const presets = [
  { id: "ssh", label: "SSH", port: 22 },
  { id: "https", label: "HTTPS", port: 443 },
  { id: "rdp", label: "RDP", port: 3389 },
  { id: "vnc", label: "VNC", port: 5900 },
  { id: "smb", label: "SMB", port: 445 },
  { id: "mongo", label: "MongoDB", port: 27017 },
  { id: "mssql", label: "SQL Server", port: 1433 },
  { id: "web8080", label: "Web", port: 8080 },
  { id: "web3000", label: "Web", port: 3000 },
  { id: "mysql", label: "MySQL", port: 3306 },
  { id: "redis", label: "Redis", port: 6379 },
  { id: "postgresql", label: "PostgreSQL", port: 5432 },
  { id: "nginx", label: "Nginx", port: 80 },
  { id: "vite", label: "Vite", port: 5173 },
  { id: "jupyter", label: "Jupyter", port: 8888 },
  { id: "tensorboard", label: "TensorBoard", port: 6006 },
];

function compare(a: Device, b: Device, prop: string) {
  if (prop === "sessions") return a.sessions - b.sessions;
  if (prop === "bytes") return a.up_bytes + a.down_bytes - (b.up_bytes + b.down_bytes);
  if (prop === "up") return a.up_bytes - b.up_bytes;
  if (prop === "down") return a.down_bytes - b.down_bytes;
  if (prop === "state") return Number(a.online) - Number(b.online);
  if (prop === "protocol") {
    const rank = (value: string) => (value === "weroxy" ? 0 : 1);
    const diff = rank(a.protocol) - rank(b.protocol);
    if (diff !== 0) return diff;
  }
  return a.name.localeCompare(b.name);
}

function onSort(event: { prop: string; order: "ascending" | "descending" | null }) {
  sortProp.value = event.prop || "name";
  sortOrder.value = event.order;
}

function generateKey() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  form.clientKey = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function openAdd() {
  error.value = "";
  form.protocol = "weroxy";
  form.clientKey = "";
  adding.value = true;
}

function publicationLabel(status?: string) {
  const labels: Record<string, string> = {
    published: "publicationVerifiedShort", unverified: "publicationUnverifiedShort",
    stale: "publicationStaleShort", missing: "publicationMissingShort",
    loopback_only: "publicationLocalShort", remapped: "publicationRemappedShort",
  };
  return t(labels[status || "unverified"] || "publicationUnverifiedShort");
}

function portOf(listen: string) {
  const index = listen.lastIndexOf(":");
  return index >= 0 ? listen.slice(index + 1) : listen;
}

function forwardKey() {
  return [form.port, form.target, form.mode, form.min, form.preferred, form.max].join("|");
}

function toneOf(code: string): NoticeTone {
  if (code === "applied") return "success";
  if (code === "failed") return "error";
  if (code === "applying" || code === "saved") return "warning";
  return "info";
}

function smallestFree() {
  const first = poolEnabled.value ? poolFirst.value : 29000;
  const last = poolEnabled.value ? poolLast.value : 65535;
  for (let port = first; port <= last; port++) {
    if (!usedPorts.value.has(port)) return String(port);
  }
  return "";
}

function textOf(value: number | null | undefined) {
  return value == null ? "" : String(value);
}

function applyForwardDefaults() {
  const item = productDefaults.value;
  if (!item) return;
  form.mode = item.mode === "exclusive" ? "exclusive" : "shared";
  form.min = item.min || 1;
  form.preferred = item.preferred || 1;
  form.max = item.max || 1;
  form.idle = textOf(item.limits.idle_sec);
  form.connect = textOf(item.limits.connect_sec);
  form.wait = textOf(item.limits.wait_sec);
  form.bandwidth = textOf(item.limits.bandwidth);
}

function applyPreset(port: number) {
  const separator = form.target.lastIndexOf(":");
  const host = separator < 0 ? form.target + ":" : form.target.slice(0, separator + 1);
  form.target = host + port;
}

function startCreate() {
  editingListen.value = "";
  form.port = smallestFree();
  form.target = "127.0.0.1:8080";
  applyForwardDefaults();
  preview.value = null;
}

watch([poolEnabled, poolFirst, poolLast, usedPorts], () => {
  if (selected.value && !editingListen.value && !portValid.value) form.port = smallestFree();
});

const policyForward = ref<Forward | null>(null);
const policyOpen = ref(false);
const policyScope = ref<"device" | "forward">("forward");
const policyTitle = computed(() => t(policyScope.value === "device" ? "devicePolicy" : "forwardPolicy"));
const policyInputs = ref<Record<string, string>>({});
const scopedCIDR = ref("");
const scopedAction = ref("ban");
const scopedMinutes = ref(30);
const scopedBusy = ref(false);
const scopedRules = computed(() => selected.value?.rules.filter(rule => rule.scope === policyScope.value && (policyScope.value === "device" || rule.listen === policyForward.value?.listen)) ?? []);
function changeScopedRule(remove?: Device["rules"][number]) {
 if(!selected.value || scopedBusy.value || (policyScope.value === "forward" && !policyForward.value)) return;
 if(!remove && (!scopedCIDR.value.trim() || !Number.isInteger(scopedMinutes.value) || scopedMinutes.value < 1 || scopedMinutes.value > 1440)) {
  notify({title:policyTitle.value,message:t(reasonText("invalid")),tone:"error"});return;
 }
 const body = remove ? {scope:remove.scope,device:selected.value.name,listen:remove.listen,cidr:remove.cidr,action:remove.action}
 : {scope:policyScope.value,device:selected.value.name,listen:policyForward.value?.listen ?? "",cidr:scopedCIDR.value.trim(),action:scopedAction.value,ttl_sec:scopedMinutes.value*60};
 confirm(policyTitle.value, `${body.cidr} · ${t("scopedAccessImpact")}`, async () => {
  if(scopedBusy.value) return;
  scopedBusy.value = true;
  try {
   const saved = await write<{status?:string}>(remove ? "/api/v1/bans/delete" : "/api/v1/bans",body);
   mark(saved.status || "saved",t("scopedAccess"),body.cidr);
   scopedCIDR.value = "";
   await load();refreshViews();
  } catch(err) { fail(err,t("noticeActionFailed")); }
  finally { scopedBusy.value = false; }
 });
}


function editForwardPolicy(row: Forward) {
 policyScope.value = "forward";
 scopedCIDR.value = "";
 policyForward.value = row;
 const own = selected.value?.policies.find((item) => item.scope === "forward" && item.listen === row.listen);
 const values = own as Record<string, unknown> | undefined;
 policyInputs.value = Object.fromEntries(policyFields.map((field) => [field.key, values?.[field.key] == null ? "" : String(values[field.key])]));
 policyOpen.value = true;
}
function editDevicePolicy() {
 if (!selected.value) return;
 policyScope.value = "device";
 scopedCIDR.value = "";
 policyForward.value = null;
 const own = selected.value.policies.find((item) => item.scope === "device");
 const values = own as Record<string, unknown> | undefined;
 policyInputs.value = Object.fromEntries(policyFields.map((field) => [field.key, values?.[field.key] == null ? "" : String(values[field.key])]));
 policyOpen.value = true;
}
function effectivePolicyValue(key: string) {
 const effective = policyScope.value === "device" ? selected.value?.effective : policyForward.value?.effective;
 const value = (effective as Record<string, unknown> | undefined)?.[key];
 return value == null ? "—" : String(value);
}
function saveForwardPolicy() {
 if (!selected.value || (policyScope.value === "forward" && !policyForward.value)) return;
 const body: Record<string, unknown> = {scope:policyScope.value,device:selected.value.name,listen:policyForward.value?.listen ?? ""};
 for (const field of policyFields) {
  const text = (policyInputs.value[field.key] ?? "").trim();
  if (text && (!/^\d+$/.test(text) || !Number.isSafeInteger(Number(text)))) {
   notify({title:t("forwardPolicy"),message:t(reasonText("invalid")),tone:"error"}); return;
  }
  body[field.key] = text ? Number(text) : null;
 }
 confirm(policyTitle.value, t(policyScope.value === "device" ? "devicePolicyImpact" : "forwardPolicyImpact"), async () => {
  try {
   const saved = await write<{status?: string}>("/api/v1/policy",body);
   mark(saved.status || "saved",policyTitle.value,String(body.listen || body.device));
   policyOpen.value = false;
   await load(); refreshViews();
  } catch(err) { fail(err,t("noticeActionFailed")); }
 });
}

function editForward(row: Forward) {
  createDraft={...form};
  editingListen.value = row.listen;
  form.port = portOf(row.listen);
  form.target = row.target;
  form.mode = row.mode === "exclusive" ? "exclusive" : "shared";
  form.min = row.min || 1;
  form.preferred = row.preferred || 1;
  form.max = row.max || 1;
  form.idle = row.effective?.idle_sec == null ? "" : String(row.effective.idle_sec);
  form.connect = row.effective?.connect_sec == null ? "" : String(row.effective.connect_sec);
  form.wait = row.effective?.wait_sec == null ? "" : String(row.effective.wait_sec);
  form.bandwidth = row.effective?.bandwidth == null ? "" : String(row.effective.bandwidth);
  preview.value = null;
  Object.assign(editDraft,form);
  if(createDraft) Object.assign(form,createDraft);
  editOpen.value=true;
}

function sessionClass(value: number) {
  if (value > 20) return "sess-20";
  if (value > 10) return "sess-10";
  if (value > 5) return "sess-5";
  return "";
}

let loadGeneration = 0;
async function load(signal?: AbortSignal) {
  const generation = ++loadGeneration;
  const [list, settings] = await Promise.all([
    api<{ devices: Device[] }>("/api/v1/devices", {signal}),
    api<Settings>("/api/v1/settings", {signal}),
  ]);
  if (signal?.aborted || generation !== loadGeneration || connectionDisposed) return;
  bindHost.value = settings.pool.bind_host || "127.0.0.1";
  poolEnabled.value = settings.pool.enabled;
  poolFirst.value = settings.pool.forward_first;
  poolLast.value = settings.pool.forward_last;
  hostOccupied.value = settings.pool.unavailable_forward ?? [];
  productDefaults.value = settings.defaults;
  devices.value = list.devices;
  if (selected.value) {
    const device = selected.value;
    const seen = await api<{ visitors: typeof visitors.value; next_cursor: string }>("/api/v1/devices/visitors?protocol=" + selected.value.protocol + "&device=" + encodeURIComponent(device.name)+"&cursor="+encodeURIComponent(visitorCursor.value), {signal});
    if (signal?.aborted || generation !== loadGeneration || selected.value?.name !== device.name || connectionDisposed) return;
    visitors.value = seen.visitors || [];
    visitorNext.value = seen.next_cursor || "";
  } else {
    visitors.value = [];
  }
  if (!defaultsReady.value) {
    applyForwardDefaults();
    defaultsReady.value = true;
  }
}

async function moreVisitors() {
  if (visitorLimit.value < visibleVisitors.value.length) {visitorLimit.value += 16; return;}
  const d=selected.value, cursor=visitorNext.value;
  if (!d || !cursor) return;
  const page=await api<{visitors: typeof visitors.value;next_cursor:string}>("/api/v1/devices/visitors?"+new URLSearchParams({protocol:d.protocol,device:d.name,cursor}));
  if (selected.value?.name!==d.name || selected.value?.protocol!==d.protocol) return;
  visitorPrevious.value.push(visitorCursor.value);visitorCursor.value=cursor;
  visitors.value=page.visitors;visitorNext.value=page.next_cursor;visitorLimit.value=16;visitorTable.value?.clearSelection();
}

async function loadConnectionPage(before = 0) {
  const device = selected.value;
  if (!device) return;
 const key=device.protocol+":"+device.name;
 if(connectionLoading.value&&connectionRequestDevice===key&&!connectionRequest?.signal.aborted) return;
 connectionRequest?.abort(); connectionRequestDevice=key;
  connectionLoading.value = true;
  const request=new AbortController(); connectionRequest=request;
  connectionError.value = "";
  const query = new URLSearchParams({ device: device.name, protocol: device.protocol, limit: "30" });
  if (before) query.set("before", String(before));
  try {
    const page = await api<{ connections: Connection[]; next_before: number }>("/api/v1/connections?" + query,{signal:request.signal});
    if (request.signal.aborted || connectionRequest !== request || selected.value?.name !== device.name || selected.value?.protocol !== device.protocol) return;
    connectionRows.value = before ? [...connectionRows.value, ...page.connections] : page.connections;
    connectionNext.value = page.next_before;
  } catch {
    if(!request.signal.aborted) connectionError.value = t("connectionUnavailable");
  } finally {
    if(connectionRequest===request) {connectionLoading.value=false;connectionRequest=null;}
  }
}

function connectionDuration(row: Connection) {
  const end = row.closed_at || new Date().toISOString();
  const seconds = Math.max(0, Math.floor((Date.parse(end) - Date.parse(row.started_at)) / 1000));
  return `${seconds}s`;
}

const { loading, stale, wake } = usePoll(load);

watch(refreshTick, () => {
  void load();
});

let connectionTimer=0;
let connectionDisposed=false;
let connectionRequest: AbortController | null=null;
let connectionRequestDevice="";
const connectionVisible=()=>!connectionDisposed&&detailTab.value==="connections"&&!!selected.value&&document.visibilityState!=="hidden";
function armConnections() {
 window.clearTimeout(connectionTimer);
 if(connectionVisible()) connectionTimer=window.setTimeout(async()=>{await loadConnectionPage();armConnections();},10000);
}
function wakeConnections() {window.clearTimeout(connectionTimer);if(connectionVisible()) void loadConnectionPage().finally(armConnections);else connectionRequest?.abort();}
watch(detailTab,wakeConnections);
onMounted(()=>document.addEventListener("visibilitychange",wakeConnections));
onUnmounted(()=>{connectionDisposed=true;window.clearTimeout(connectionTimer);connectionRequest?.abort();document.removeEventListener("visibilitychange",wakeConnections);});

function confirm(title: string, detail: string, run: () => Promise<void>) {
  if (actionBusy.value) return;
  ask.value = { title, detail, run };
}

async function runConfirm() {
  if (actionBusy.value || !ask.value) return;
  const job = ask.value;
  ask.value = null;
  actionBusy.value = true;
  try { await job.run(); } catch (err) { fail(err, t("noticeActionFailed")); } finally { actionBusy.value = false; }
}

function mark(status: string, title: string, detail = "", deploymentRequired = false) {
  notice.value = status || "saved";
  error.value = "";
  const note = t("status_" + notice.value);
  const message = [detail, note, deploymentRequired ? t("deployment_required") : ""].filter(Boolean).join("\n");
  notify({ title, message, tone: deploymentRequired ? "warning" : toneOf(notice.value) });
}

function fail(err: unknown, title: string) {
  notice.value = "failed";
  error.value = t(reasonText(err instanceof ApiError ? err.code : "invalid"));
  notify({ title, message: error.value, tone: "error" });
}

async function write<T>(path: string, body: unknown): Promise<T> {
  return api<T>(path, { method: "POST", body: JSON.stringify(body) });
}

async function createDevice() {
  if (actionBusy.value) return;
  actionBusy.value = true;
  const input = { name: form.name, protocol: form.protocol, client_key: form.clientKey };
  error.value = "";
  try {
    const created = await api<{ status?: ApplyStatus }>("/api/v1/devices", {
      method: "POST",
      body: JSON.stringify(input),
    });
    adding.value = false;
    form.clientKey = "";
    mark(created.status || "saved", t("noticeDeviceAdded"), input.name);
    await load();
    refreshViews();
    router.push("/devices/" + encodeURIComponent(input.name));
  } catch (err) {
    fail(err, t("noticeActionFailed"));
  } finally { actionBusy.value = false; }
}

function copySelectedKey() {
  const field = document.querySelector<HTMLInputElement>(".port-top .el-input__inner");
  if (!field || field.value !== form.clientKey) return false;
  field.focus();
  field.select();
  // execCommand must run in the click handler before an awaited permission check.
  return document.execCommand("copy");
}

async function copyKey() {
  if (!form.clientKey) return;
  if (!window.isSecureContext || !navigator.clipboard?.writeText) {
    if (copySelectedKey()) notify({ title: t("noticeCopied"), tone: "success" });
    else notify({ title: t("copyFailed"), message: t("copyFailedHint"), tone: "warning" });
    return;
  }
  try {
    await navigator.clipboard.writeText(form.clientKey);
    notify({ title: t("noticeCopied"), tone: "success" });
  } catch {
    if (copySelectedKey()) notify({ title: t("noticeCopied"), tone: "success" });
    else notify({ title: t("copyFailed"), message: t("copyFailedHint"), tone: "warning" });
  }
}

function keyID(protocol: string, name: string) {
  return protocol + "\n" + name;
}

function requestSaveKey() {
  if (!selected.value || actionBusy.value) return;
  const device = selected.value;
  const key = form.clientKey.trim();
  confirm(t("save"), t("keyChangeImpact"), () => saveKey(device, key));
}

function revokeCredential() {
  if (!selected.value || actionBusy.value || selected.value.protocol !== "weroxy") return;
  const device = selected.value;
  confirm(t("revokeDevice"), t("revokeCredentialImpact"), async () => {
    const saved = await write<{status?: string}>("/api/v1/devices/revoke", {name: device.name, protocol: device.protocol});
    savedKeys.delete(keyID(device.protocol, device.name));
    if (selected.value?.name === device.name && selected.value?.protocol === device.protocol) form.clientKey = "";
    mark(saved.status || "saved", t("revokeDevice"), device.name);
    await load(); refreshViews();
  });
}

async function saveKey(device: Device, key: string) {
  if (!key) {
    notify({ title: t("noticeKeyEmpty"), message: t("noticeKeyEmptyBody"), tone: "warning" });
    return;
  }
  try {
    const saved = await write<{ duplicate?: boolean; token?: string; client_key?: string; status?: string; deployment_required?: boolean }>("/api/v1/devices/key", {
      name: device.name,
      protocol: device.protocol,
      client_key: key,
    });
    const isCurrent = () => selected.value?.name === device.name && selected.value?.protocol === device.protocol;
    if (saved.duplicate) {
      savedKeys.delete(keyID(device.protocol, device.name));
      if (isCurrent()) form.clientKey = "";
      await load();
      if (isCurrent()) form.clientKey = selected.value?.client_key || "";
    } else {
      const savedKey = saved.token || saved.client_key || key;
      savedKeys.set(keyID(device.protocol, device.name), savedKey);
      if (isCurrent()) form.clientKey = savedKey;
    }
    mark(saved.status || "saved", t("noticeKeySaved"), "", saved.deployment_required);
  } catch (err) {
    fail(err, t("noticeActionFailed"));
  }
}

async function runPreview() {
  if (!selected.value || previewBusy.value) return;
  error.value = "";
  if (!portValid.value) {
    notify({ title: t("noticeForwardRejected"), message: portHint.value, tone: "error" });
    return;
  }
  const body = forwardBody();
  const key = forwardKey();
  previewBusy.value = true;
  try {
    const result = await api<Preview>("/api/v1/forwards/preview", {
      method: "POST",
      body: JSON.stringify(body),
    });
    if (forwardKey() !== key) return;
    preview.value = result;
    previewKey.value = key;
    if (!result.ok) notice.value = "failed";
  } catch (err) {
    fail(err, t("noticeForwardRejected"));
  } finally { previewBusy.value = false; }
}

function forwardBody() {
  return {
    device: selected.value?.name,
    protocol: selected.value?.protocol,
    listen: bindHost.value + ":" + form.port,
    previous_listen: editingListen.value || "",
    target: form.target,
    mode: selected.value?.protocol === "weroxy" ? form.mode : "",
    min: form.min,
    preferred: form.preferred,
    max: form.max,
    manual_data_ports: [],
  };
}

async function saveForward() {
  if (actionBusy.value || previewBusy.value) return;
  if (!portValid.value) {
    notify({ title: t("noticeForwardRejected"), message: portHint.value, tone: "error" });
    return;
  }
  if (!freshPreview.value) await runPreview();
  if (!freshPreview.value || !preview.value?.ok) {
    const code = preview.value?.error || "invalid";
    notify({ title: t("noticeForwardRejected"), message: t(reasonText(code)), tone: "error" });
    return;
  }
  const body = forwardBody();
  confirm(t("save"), t("forwardPublishImpact"), () => commitForward(body));
}

watch(() => selected.value?.name, (name, previous) => {
  if (name === previous) return;
  editOpen.value = false;
  renameOpen.value = false;
  connectionRequest?.abort();
  visitors.value = [];
  visitorCursor.value="";visitorPrevious.value=[];visitorNext.value="";visitorLimit.value=16;
  visitorTable.value?.clearSelection();
  banTable.value?.clearSelection();
  pickedVisitors.value = [];
  pickedBans.value = [];
  if (!name || !selected.value) return;
  ask.value = null;
  policyOpen.value = false;
  policyForward.value = null;
  form.clientKey = savedKeys.get(keyID(selected.value.protocol, name)) || selected.value.client_key || "";
  startCreate();
  connectionRequest?.abort();
  connectionRows.value = [];
  connectionNext.value = 0;
  if (detailTab.value === "connections") queueMicrotask(wakeConnections);
});

watch(() => selected.value?.client_key, (key) => {
  if (key && !form.clientKey) form.clientKey = key;
});

async function commitForward(body: ReturnType<typeof forwardBody>) {
  const isCurrent = () => selected.value?.name === body.device && selected.value?.protocol === body.protocol;
  try {
    const previous = body.previous_listen;
    const saved = await write<{ status?: string; deployment_required?: boolean }>("/api/v1/forwards", body);
    if (isCurrent()) { preview.value = null; editingListen.value = ""; }
    const title = previous ? t("noticeForwardUpdated") : t("noticeForwardSaved");
    mark(saved.status || "saved", title, `${body.listen} → ${body.target}`, saved.deployment_required);
    await load();
    refreshViews();
    if (isCurrent()) startCreate();
  } catch (err) {
    fail(err, t("noticeForwardRejected"));
  }
}

function removeForward(listen: string) {
  if (!selected.value) return;
  const device = selected.value;
  confirm(t("remove"), listen, async () => {
    try {
      const saved = await write<{ status?: string; deployment_required?: boolean }>("/api/v1/forwards/delete", { device: device.name, protocol: device.protocol, listen });
      mark(saved.status || "saved", t("noticeForwardRemoved"), listen, saved.deployment_required);
      await load();
      refreshViews();
    } catch (err) {
      fail(err, t("noticeActionFailed"));
    }
  });
}

function grow(limit: { value: number }, total: number) {
  if (limit.value < total) limit.value += 16;
}

function onLazy(table: { $el?: HTMLElement } | null, section: "list" | "forward" | "visitor" | "ban", total: number) {
  const wrap = table?.$el?.querySelector(".el-scrollbar__wrap") as HTMLElement | null;
  if (!wrap) return;
  if (wrap.scrollTop + wrap.clientHeight >= wrap.scrollHeight - 40) grow({ list: listLimit, forward: forwardLimit, visitor: visitorLimit, ban: banLimit }[section], total);
}

async function banMany() {
  const device = selected.value;
  const rows = pickedVisitors.value.filter(row => visibleVisitors.value.some(v => v.ip === row.ip));
  if (!device || rows.length === 0) return;
  try {
    for (const row of rows) {
      const cidr = row.ip.includes(":") ? row.ip + "/128" : row.ip + "/32";
      await write("/api/v1/bans", { scope: "device", device: device.name, listen: "", cidr, action: "ban" });
    }
    const count = rows.length;
    visitorTable.value?.clearSelection();
    pickedVisitors.value = [];
    mark("saved", t("noticeBatchBanned"), String(count));
    await load();
    refreshViews();
  } catch (err) {
    fail(err, t("noticeActionFailed"));
  }
}

async function unbanMany() {
  const device = selected.value;
  const rows = pickedBans.value.filter(row => device?.rules.some(v => v.scope === row.scope && v.listen === row.listen && v.cidr === row.cidr && v.action === "ban"));
  if (!device || rows.length === 0) return;
  try {
    for (const rule of rows) {
      await write("/api/v1/bans/delete", {
        scope: rule.scope,
        device: device.name,
        listen: rule.listen,
        cidr: rule.cidr,
        action: rule.action,
      });
    }
    const count = rows.length;
    banTable.value?.clearSelection();
    pickedBans.value = [];
    mark("saved", t("noticeBatchUnbanned"), String(count));
    await load();
    refreshViews();
  } catch (err) {
    fail(err, t("noticeActionFailed"));
  }
}

function banVisitor(ip: string) {
  if (!selected.value) return;
  const cidr = ip.includes(":") ? ip + "/128" : ip + "/32";
  confirm(t("ban"), cidr, async () => {
    try {
      const saved = await write<{ status?: string }>("/api/v1/bans", {
        scope: "device",
        device: selected.value?.name,
        listen: "",
        cidr,
        action: "ban",
      });
      mark(saved.status || "saved", t("noticeBanned"), cidr);
      await load();
      refreshViews();
    } catch (err) {
      fail(err, t("noticeActionFailed"));
    }
  });
}

function removeBan(rule: Device["rules"][number]) {
  if (!selected.value) return;
  confirm(t("unban"), rule.cidr, async () => {
    try {
      const saved = await write<{ status?: string }>("/api/v1/bans/delete", {
        scope: rule.scope,
        device: selected.value?.name,
        listen: rule.listen,
        cidr: rule.cidr,
        action: rule.action,
      });
      mark(saved.status || "saved", t("noticeUnbanned"), rule.cidr);
      await load();
      refreshViews();
    } catch (err) {
      fail(err, t("noticeActionFailed"));
    }
  });
}

async function switchProtocol(row: Device) {
  try {
    const saved = await write<{ status?: string; protocol?: string }>("/api/v1/devices/protocol", {
      name: row.name,
      protocol: row.protocol,
    });
    const next = saved.protocol === "legacy" ? "Legacy" : "Weroxy";
    mark(saved.status || "saved", t("noticeSwitched"), `${row.name} · ${next}`);
    await load();
    refreshViews();
  } catch (err) {
    fail(err, t("noticeActionFailed"));
  }
}

async function toggleDevice(row: Device) {
  if (actionBusy.value) return;
  actionBusy.value = true;
  try {
    const saved = await write<{ status?: string }>("/api/v1/devices/paused", {
      name: row.name,
      protocol: row.protocol,
      paused: !row.paused,
    });
    mark(saved.status || "saved", row.paused ? t("noticeResumed") : t("noticePaused"), row.name);
    await load();
    refreshViews();
  } catch (err) {
    fail(err, t("noticeActionFailed"));
  } finally { actionBusy.value = false; }
}

function removeDevice(row: Device) {
  confirm(t("deleteDevice"), row.name, async () => {
    try {
      const saved = await write<{ status?: string; deployment_required?: boolean }>("/api/v1/devices/delete", { name: row.name, protocol: row.protocol });
      mark(saved.status || "saved", t("noticeDeviceRemoved"), row.name, saved.deployment_required);
      await load();
      refreshViews();
      if (route.params.name === row.name) router.push("/devices");
    } catch (err) {
      fail(err, t("noticeActionFailed"));
    }
  });
}

const renameOpen=ref(false),renameName=ref(""),renameBusy=ref(false);
let renameRow:Device|null=null;
function openRename(row:Device){renameRow=row;renameName.value=row.name;renameOpen.value=true;}
async function saveRename(){if(!renameRow||renameBusy.value)return;const row=renameRow;renameBusy.value=true;try{await api("/api/v1/devices/rename",{method:"POST",body:JSON.stringify({protocol:row.protocol,name:row.name,new_name:renameName.value.trim()})});renameOpen.value=false;await load();refreshViews();if(route.params.name===row.name)await router.replace('/devices/'+encodeURIComponent(renameName.value.trim()));notify({title:t('saved'),tone:'success'});}catch(e){fail(e,t('rename'));}finally{renameBusy.value=false;}}
function removeVisitors(ips:string[]){if(!selected.value||!ips.length)return;const d=selected.value;confirm(t('deleteVisitor'),ips.join(', '),async()=>{const r=await api<{deleted:string[];skipped_active:string[]}>("/api/v1/devices/visitors/delete",{method:'POST',body:JSON.stringify({device:d.name,protocol:d.protocol,ips})});visitorTable.value?.clearSelection();pickedVisitors.value=[];await load();notify({title:t('deleteVisitor'),message:r.skipped_active.length?t('visitorDeleteBusy',{count:r.skipped_active.length}):t('saved'),tone:r.skipped_active.length?'warning':'success'});});}
const editPorts=computed(()=>Array.from(new Set([...availablePorts.value,portOf(editingListen.value)])));
const editValid=computed(()=>{const p=Number(editDraft.port);return /^\d+$/.test(editDraft.port)&&p>0&&p<65536&&(editDraft.port===portOf(editingListen.value)||(!usedPorts.value.has(p)&&!hostOccupied.value.includes(p)&&(!poolEnabled.value||(p>=poolFirst.value&&p<=poolLast.value))));});
const editHint=computed(()=>editValid.value?t('portPoolHint',{first:poolFirst.value,last:poolLast.value,count:freePortCount.value}):t('portInvalidHint',{first:poolFirst.value,last:poolLast.value}));
function editPreset(port:number){const i=editDraft.target.lastIndexOf(':');editDraft.target=editDraft.target.slice(0,i+1)+port;}
function cancelEdit(){editingListen.value='';preview.value=null;createDraft=null;}
async function saveEdit(){if(!editValid.value||actionBusy.value||previewBusy.value||!selected.value)return;const d=selected.value;const body={device:d.name,protocol:d.protocol,listen:bindHost.value+':'+editDraft.port,previous_listen:editingListen.value,target:editDraft.target,mode:d.protocol==='weroxy'?editDraft.mode:'',min:editDraft.min,preferred:editDraft.preferred,max:editDraft.max,manual_data_ports:[]};previewBusy.value=true;try{const v=await api<Preview>('/api/v1/forwards/preview',{method:'POST',body:JSON.stringify(body)});if(!v.ok)throw new ApiError(v.error||'invalid');confirm(t('save'),t('forwardPublishImpact'),async()=>{await write('/api/v1/forwards',body);editOpen.value=false;await load();refreshViews();notify({title:t('noticeForwardUpdated'),tone:'success'});});}catch(e){fail(e,t('noticeForwardRejected'));}finally{previewBusy.value=false;}}

</script>

<template>
 <div class="devices-root">
  <main class="page" v-loading="loading && devices.length === 0" v-if="!route.params.name">
    <el-alert v-if="stale" :title="t('stale')" type="warning" show-icon :closable="false" style="margin-bottom: 12px" />
    <div class="toolbar">
      <el-input v-model="filters.q" :placeholder="t('search')" clearable style="max-width: 240px" />
      <el-select v-model="filters.protocol" style="width: 140px">
        <el-option :label="t('all')" value="all" />
        <el-option label="Weroxy" value="weroxy" />
        <el-option label="Legacy" value="legacy" />
      </el-select>
      <el-button type="primary" @click="openAdd">{{ t("addClient") }}</el-button>
    </div>
    <el-table ref="deviceTable" :data="paged" max-height="480" @sort-change="onSort" @scroll="onLazy(deviceTable, 'list', ranked.length)">
      <el-table-column prop="name" :label="t('name')" width="220" sortable="custom">
        <template #default="{ row }">
          <router-link class="name-link" :to="'/devices/' + row.name">{{ row.name }}</router-link>
        </template>
      </el-table-column>
      <el-table-column prop="protocol" :label="t('protocol')" width="100">
        <template #default="{ row }">
          <el-tag :class="row.protocol === 'weroxy' ? 'tag-weroxy' : 'tag-legacy'">{{ row.protocol === "weroxy" ? "Weroxy" : "Legacy" }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="sessions" :label="t('sessions')" width="110" sortable="custom">
        <template #default="{ row }"><span :class="sessionClass(row.sessions)">{{ row.sessions }}</span></template>
      </el-table-column>
      <el-table-column :label="t('up')" prop="up" width="100" sortable="custom">
        <template #default="{ row }">{{ formatBytes(row.up_bytes) }}</template>
      </el-table-column>
      <el-table-column :label="t('down')" prop="down" width="100" sortable="custom">
        <template #default="{ row }">{{ formatBytes(row.down_bytes) }}</template>
      </el-table-column>
      <el-table-column :label="t('traffic')" prop="bytes" min-width="110" sortable="custom">
        <template #default="{ row }">{{ formatBytes(row.up_bytes + row.down_bytes) }}</template>
      </el-table-column>
      <el-table-column :label="t('state')" prop="state" width="110" sortable="custom" class-name="cell-nowrap">
        <template #default="{ row }">
          <el-tag :type="row.online_known === false ? 'warning' : row.online ? 'success' : 'danger'">{{ row.online_known === false ? t("unknown") : row.online ? t("online") : t("offline") }}</el-tag>
          <el-tag v-if="row.paused" type="danger" style="margin-left: 6px">{{ t("pause") }}</el-tag>
          <el-tag v-if="row.revoked" type="danger" style="margin-left: 6px">{{ t("revokeDevice") }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="t('actions')" fixed="right" width="148" align="right">
        <template #default="{ row }">
          <span class="row-actions">
            <IconButton name="rename" :label="t('rename')" @click.stop="openRename(row)" />
            <IconButton name="swap" :label="row.protocol === 'weroxy' ? t('toLegacy') : t('toWeroxy')" @click.stop="switchProtocol(row)" />
            <IconButton :name="row.paused ? 'play' : 'pause'" :label="row.paused ? t('resume') : t('pause')" @click.stop="toggleDevice(row)" />
            <IconButton name="trash" danger :label="t('deleteDevice')" @click.stop="removeDevice(row)" />
          </span>
        </template>
      </el-table-column>
      <template #empty>
        <el-empty :description="t('noDevices')" />
      </template>
    </el-table>

    <el-button v-if="listLimit < ranked.length" @click="listLimit += 16">{{ t("loadMore") }}</el-button>
    <el-button v-if="stale" @click="wake">{{ t("refresh") }}</el-button>

    <el-dialog v-model="adding" :title="t('addClient')" width="min(440px, calc(100vw - 24px))">
      <el-form label-position="top" @submit.prevent>
        <el-form-item :label="t('name')"><el-input v-model="form.name" /></el-form-item>
        <el-form-item :label="t('protocol')">
          <el-select v-model="form.protocol">
            <el-option label="Weroxy" value="weroxy" />
            <el-option label="Legacy" value="legacy" />
          </el-select>
        </el-form-item>
        <el-form-item :label="t('clientKey')">
          <div class="toolbar">
            <el-input v-model="form.clientKey" :disabled="actionBusy" />
            <el-button :disabled="actionBusy" @click="generateKey">{{ t("generate") }}</el-button>
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button type="primary" :loading="actionBusy" :disabled="actionBusy" @click="createDevice">{{ t("save") }}</el-button>
      </template>
    </el-dialog>
  </main>

  <main class="page" :class="{ 'management-page': detailTab === 'manage' }" v-else-if="selected">
    <el-alert v-if="stale" :title="t('stale')" type="warning" show-icon :closable="false" style="margin-bottom: 12px" />
    <header class="device-detail-head"><h2 :title="selected.name">{{ selected.name }}</h2>
    <div class="tags">
      <el-tag :class="selected.protocol === 'weroxy' ? 'tag-weroxy' : 'tag-legacy'">{{ selected.protocol === "weroxy" ? "Weroxy" : "Legacy" }}</el-tag>
      <el-tag :type="selected.online_known === false ? 'warning' : selected.online ? 'success' : 'danger'">{{ selected.online_known === false ? t("unknown") : selected.online ? t("online") : t("offline") }}</el-tag>
      <el-tag v-if="selected.revoked" type="danger">{{ t("revokeDevice") }}</el-tag>
      <el-tag v-if="selected.protocol !== 'legacy' && selected.client_version" type="info">{{ selected.client_version }}</el-tag>
    </div><el-button class="device-policy" @click="editDevicePolicy">{{ t("devicePolicy") }}</el-button></header>
    <p v-if="selected.protocol === 'legacy'" class="hint">{{ t("legacyFixed") }}</p>

    <el-tabs v-model="detailTab">
      <el-tab-pane :label="t('ports')" name="ports">
        <div v-if="selected.protocol === 'weroxy'" class="port-summary"><el-tooltip :content="t('physicalPortHint')"><span>{{ t('physicalPortUnion') }} <b>{{ selected.data_physical_count ?? '—' }}</b></span></el-tooltip><el-tooltip :content="t('allocationHint')"><span>{{ t('allocationCount') }} <b>{{ selected.data_allocation_count ?? '—' }}</b></span></el-tooltip></div>
        <div class="port-top">
          <section class="form-block credential-block">
            <h3>{{ t("clientKey") }}</h3>
            <div class="credential-row">
              <el-input v-model="form.clientKey" :disabled="actionBusy" :aria-label="t('clientKey')" />
              <div class="form-actions credential-actions">
                <el-button type="primary" :loading="actionBusy" :disabled="actionBusy" @click="requestSaveKey">{{ t("save") }}</el-button>
                <el-button @click="copyKey">{{ t("copy") }}</el-button>
                <el-button v-if="selected.protocol === 'weroxy'" type="danger" :disabled="actionBusy || selected.revoked" @click="revokeCredential">{{ t("revokeDevice") }}</el-button>
                <el-button @click="generateKey">{{ t("random") }}</el-button>
              </div>
            </div>
          </section>
          <el-drawer v-model="policyOpen" :title="policyTitle" size="min(480px, 100vw)" append-to-body>
            <p>{{ policyScope === "device" ? selected.name : policyForward?.listen }}</p>
            <p class="reason">{{ t("forwardPolicyHint") }}</p>
            <el-button v-if="policyScope === 'forward'" @click="policyInputs.rate='5';policyInputs.burst='10'">{{ t("sshPolicyPreset") }}</el-button>
            <el-form label-position="top" @submit.prevent="saveForwardPolicy">
              <el-form-item v-for="field in policyFields" :key="field.key" :label="`${t(field.label)} · ${t('policyEffective')}: ${effectivePolicyValue(field.key)}`">
                <el-input v-model="policyInputs[field.key]" inputmode="numeric" :placeholder="t('policyInherit')" />
              </el-form-item>
              <el-button native-type="submit" type="primary">{{ t("save") }}</el-button>
            </el-form>
            <h3>{{ t("scopedAccess") }}</h3>
            <p class="reason">{{ t("scopedAccessHint") }}</p>
            <el-form label-position="top" @submit.prevent="changeScopedRule()">
              <el-form-item label="CIDR"><el-input v-model="scopedCIDR" placeholder="192.0.2.0/24" /></el-form-item>
              <el-form-item :label="t('auditAction')"><el-select v-model="scopedAction"><el-option value="ban" :label="t('globalRuleBan')" /><el-option value="allow" :label="t('globalRuleAllow')" /></el-select></el-form-item>
              <el-form-item :label="t('globalRuleMinutes')"><el-input-number v-model="scopedMinutes" :min="1" :max="1440" :precision="0" /></el-form-item>
              <el-button native-type="submit" type="primary" :loading="scopedBusy">{{ t("add") }}</el-button>
            </el-form>
            <el-table :data="scopedRules" size="small" max-height="300">
              <el-table-column prop="cidr" label="CIDR" min-width="130" />
              <el-table-column :label="t('auditAction')"><template #default="scope">{{ t(scope.row.action === 'ban' ? 'globalRuleBan' : 'globalRuleAllow') }}</template></el-table-column>
              <el-table-column :label="t('sessionExpires')" min-width="150"><template #default="scope">{{ scope.row.expires_at ? new Date(scope.row.expires_at).toLocaleString() : '—' }}</template></el-table-column>
              <el-table-column><template #default="scope"><el-button text :disabled="scopedBusy" @click="changeScopedRule(scope.row)">{{ t("remove") }}</el-button></template></el-table-column>
            </el-table>
          </el-drawer>
          <ForwardForm
            v-model:port="form.port"
            v-model:target="form.target"
            :title="t('addForward')"
            :editing="false"
            :busy="actionBusy || previewBusy || editOpen"
            :available-ports="availablePorts"
            :pool-enabled="poolEnabled"
            :port-hint="portHint"
            :port-valid="portValid"
            :presets="presets"
            :labels="{
              publicPort: t('publicPort'),
              lanAddress: t('lanAddress'),
              add: t('add'),
              create: t('newForward'),
              preset: t('preset'),
            }"
            @preset="applyPreset"
            @save="saveForward"
            @create="startCreate"
          >
            <template v-if="selected.protocol === 'weroxy'">
              <el-form-item :label="t('dataPortPolicy')">
                <el-select v-model="form.mode"><el-option :label="t('shared')" value="shared" /><el-option :label="t('exclusive')" value="exclusive" /></el-select>
              </el-form-item>
              <el-form-item :label="t('minPorts')"><el-input-number v-model="form.min" :min="1" :max="form.preferred" /></el-form-item>
              <el-form-item :label="t('preferredPorts')"><el-input-number v-model="form.preferred" :min="form.min" :max="form.max" /></el-form-item>
              <el-form-item :label="t('maxPorts')"><el-input-number v-model="form.max" :min="form.preferred" :max="200" /></el-form-item>
            </template>

          </ForwardForm>
        </div>
        <el-table class="forward-table" ref="forwardTable" :data="shownForwards" max-height="360" @scroll="onLazy(forwardTable, 'forward', selected.forwards.length)">
          <el-table-column :label="t('publicPort')" width="95">
            <template #default="{ row }">{{ portOf(row.listen) }}</template>
          </el-table-column>
          <el-table-column prop="target" :label="t('lanAddress')" width="190" show-overflow-tooltip>
            <template #default="{row}">{{ row.target }}<small v-if="[22,2222,3389].includes(Number(row.target.split(':').pop()))" class="reason">{{ t('sensitiveTargetHint') }}</small></template>
          </el-table-column>
          <el-table-column :label="t('traffic')" min-width="110"><template #default="{ row }"><div class="forward-traffic"><span>↑ {{ formatBytes(row.up_bytes ?? 0) }}</span><span>↓ {{ formatBytes(row.down_bytes ?? 0) }}</span></div></template></el-table-column>
          <el-table-column v-if="selected.protocol === 'weroxy'" :label="t('dataPorts')" width="95">
            <template #default="{ row }">
              <el-tooltip placement="top" popper-class="forward-detail-tooltip">
                <template #content>
                  <template v-if="row.runtime_known">
                    <div>{{ t('healthyPorts') }} {{ row.data_healthy }} / {{ t('assigned') }} {{ row.data_current }}</div>
                    <div>{{ t('availableMax') }} {{ row.available_max }} · {{ t('canGrow') }} {{ row.can_grow }} · Drain {{ row.data_draining }}</div>
                    <div v-if="row.data_ports?.length">{{ t('dataPorts') }}: {{ row.data_ports.join(', ') }}</div>
                    <div v-for="reason in row.limiting_reasons || []" :key="reason">{{ t(reasonText(reason)) }}</div>
                  </template>
                  <span v-else>{{ t('runtimeUnknown') }}</span>
                </template>
                <span class="capacity-value" tabindex="0">
                  <template v-if="row.runtime_known">{{ row.data_healthy }} / {{ row.data_current }}</template>
                  <template v-else>{{ t('unknownShort') }}</template>
                  <el-tag v-if="row.limiting_reasons?.length" size="small" type="warning">!</el-tag>
                </span>
              </el-tooltip>
              <div v-if="row.runtime_known" class="capacity-caption">{{ t('capacityRatio') }}</div>
            </template>
          </el-table-column>
          <el-table-column v-if="selected.protocol === 'weroxy'" :label="t('publicationShort')" width="96">
            <template #default="{ row }">
              <el-tooltip :content="t('portPublish_' + (row.publication_status || 'unverified'))" placement="top" popper-class="forward-detail-tooltip">
                <el-tag size="small" :type="row.publication_status === 'published' ? 'success' : row.publication_status === 'missing' ? 'danger' : 'warning'">{{ publicationLabel(row.publication_status) }}</el-tag>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column v-if="selected.protocol === 'weroxy'" :label="t('deviceReachability')" width="100">
            <template #default="{ row }">
              <el-tooltip :content="row.device_reachability === 'reachable' ? t('reachabilityVerified') : row.device_reachability === 'unreachable' ? t('deviceDataUnreachable') : t('reachabilityUnknown')" placement="top" popper-class="forward-detail-tooltip">
                <el-tag size="small" :type="row.device_reachability === 'reachable' ? 'success' : row.device_reachability === 'unreachable' ? 'danger' : 'warning'">{{ row.device_reachability === 'reachable' ? t('verifiedShort') : row.device_reachability === 'unreachable' ? t('failedShort') : t('unknownShort') }}</el-tag>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column :label="t('state')" width="80">
            <template #default="{ row }"><el-tag :type="row.enabled === false ? 'danger' : 'success'">{{ row.enabled === false ? t("disabled") : t("enabled") }}</el-tag></template>
          </el-table-column>
          <el-table-column :label="t('actions')" fixed="right" width="104" align="center">
            <template #default="{ row }">
              <span class="row-actions forward-row-actions">
                <IconButton name="edit" :label="t('editForward')" @click.stop="editForward(row)" />
                <IconButton name="policy" :label="t('forwardPolicy')" @click.stop="editForwardPolicy(row)" />
                <IconButton name="trash" danger :label="t('remove')" @click.stop="removeForward(row.listen)" />
              </span>
            </template>
          </el-table-column>
          <template #empty><el-empty :description="t('empty')" /></template>
        </el-table>
        <el-button v-if="forwardLimit < selected.forwards.length" @click="forwardLimit += 16">{{ t("loadMore") }}</el-button>
      </el-tab-pane>

      <el-tab-pane :label="t('connectionDetails')" name="connections">
        <div class="toolbar connection-toolbar">
          <el-button @click="loadConnectionPage()" :loading="connectionLoading">{{ t("refresh") }}</el-button>
        </div>
        <el-alert v-if="connectionError" :title="connectionError" type="warning" :closable="false" />
        <el-table :data="connectionRows" v-loading="connectionLoading" max-height="430">
          <el-table-column prop="source_ip" label="IP" min-width="120" />
          <el-table-column prop="forward_listen" :label="t('listen')" min-width="135" />
          <el-table-column :label="t('dataPorts')" width="90">
            <template #default="{ row }">{{ row.data_port || "—" }}</template>
          </el-table-column>
          <el-table-column :label="t('startTime')" min-width="175">
            <template #default="{ row }">{{ new Date(row.started_at).toLocaleString() }}</template>
          </el-table-column>
          <el-table-column :label="t('duration')" width="90">
            <template #default="{ row }">{{ connectionDuration(row) }}</template>
          </el-table-column>
          <el-table-column :label="t('up')" width="95">
            <template #default="{ row }">{{ formatBytes(row.up_bytes) }}</template>
          </el-table-column>
          <el-table-column :label="t('down')" width="95">
            <template #default="{ row }">{{ formatBytes(row.down_bytes) }}</template>
          </el-table-column>
          <el-table-column :label="t('state')" width="90">
            <template #default="{ row }"><el-tag class="connection-state" :type="row.status === 'active' ? 'success' : 'danger'" effect="light">{{ row.status === "active" ? t("connectionActive") : t("connectionClosed") }}</el-tag></template>
          </el-table-column>
          <el-table-column prop="close_reason" :label="t('closeReason')" min-width="125" />
          <template #empty><el-empty :description="t('empty')" /></template>
        </el-table>
        <el-button v-if="connectionNext" text :loading="connectionLoading" @click="loadConnectionPage(connectionNext)">{{ t("loadMore") }}</el-button>
      </el-tab-pane>

      <el-tab-pane :label="t('manage')" name="manage">
        <div class="forward-split management-grid">
          <section class="form-block">
            <header class="management-head"><h3>{{ t("connectedDevices") }}</h3><div><el-button type="danger" :disabled="pickedVisitors.length === 0" @click="banMany">{{ t("batchBan") }}</el-button><el-button :disabled="!pickedVisitors.some(row => !row.active)" @click="removeVisitors(pickedVisitors.filter(row => !row.active).map(row => row.ip))">{{ t("batchDelete") }}</el-button></div></header>
            <el-table ref="visitorTable" row-key="ip" :data="shownVisitors" height="100%" @selection-change="pickedVisitors = $event" @scroll="onLazy(visitorTable, 'visitor', visibleVisitors.length)">
              <el-table-column type="selection" width="42" reserve-selection />
              <el-table-column prop="ip" label="IP" min-width="140" />
              <el-table-column :label="t('state')" width="125">
                <template #default="{ row }"><el-tag :type="row.active ? 'success' : 'danger'">{{ row.active ? `${t("online")} · ${row.active_connections}` : t("offline") }}</el-tag></template>
              </el-table-column>
              <el-table-column prop="connections" :label="t('connections')" width="90" />
              <el-table-column :label="t('trafficTotal')" width="105">
                <template #default="{ row }">{{ formatBytes(row.bytes) }}</template>
              </el-table-column>
              <el-table-column :label="t('actions')" fixed="right" width="90" align="right">
                <template #default="{ row }">
                  <span class="row-actions">
                    <IconButton v-if="!row.active" name="trash" danger :label="t('deleteVisitor')" @click.stop="removeVisitors([row.ip])" />
                    <IconButton name="ban" danger :label="t('ban')" @click.stop="banVisitor(row.ip)" />
                  </span>
                </template>
              </el-table-column>
              <template #empty><el-empty :description="t('empty')" /></template>
            </el-table>
            <el-button v-if="visitorPrevious.length" @click="visitorCursor=visitorPrevious.pop() || '';visitorLimit=16;load()">{{ t("previous") }}</el-button>
            <el-button v-if="visitorLimit < visibleVisitors.length || visitorNext" @click="moreVisitors">{{ t("loadMore") }}</el-button>
          </section>
          <section class="form-block">
            <header class="management-head"><h3>{{ t("bannedDevices") }}</h3><el-button :disabled="pickedBans.length === 0" @click="unbanMany">{{ t("batchUnban") }}</el-button></header>
            <el-table ref="banTable" :row-key="banRowKey" :data="shownBans" height="100%" @selection-change="pickedBans = $event" @scroll="onLazy(banTable, 'ban', selected.rules.filter((rule) => rule.action === 'ban').length)">
              <el-table-column type="selection" width="42" reserve-selection />
              <el-table-column prop="cidr" label="IP" min-width="118" show-overflow-tooltip />
              <el-table-column prop="scope" :label="t('mode')" width="90" />
              <el-table-column prop="listen" :label="t('listen')" width="72" />
              <el-table-column :label="t('actions')" fixed="right" width="94" align="right">
                <template #default="{ row }">
                  <span class="row-actions">
                    <el-button class="unban-action" type="success" plain size="small" @click.stop="removeBan(row)"><svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 0a3 3 0 0 0-3 3v3H4a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2H6V3a2 2 0 0 1 4 0h1a3 3 0 0 0-3-3M4 7h8a1 1 0 0 1 1 1v6a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V8a1 1 0 0 1 1-1"/></svg>{{ t("unban") }}</el-button>
                  </span>
                </template>
              </el-table-column>
              <template #empty><el-empty :description="t('empty')" /></template>
            </el-table>
            <el-button v-if="banLimit < selected.rules.filter(rule => rule.action === 'ban').length" @click="banLimit += 16">{{ t("loadMore") }}</el-button>
          </section>
        </div>

      </el-tab-pane>
    </el-tabs>

  </main>

  <main class="page" v-else :aria-busy="loading">
    <p v-if="loading" role="status">{{ t("loading") }}</p>
    <el-alert v-else-if="stale" :title="t('stale')" type="error" show-icon :closable="false" />
    <el-empty v-else :description="t('notFound')" />
    <el-button v-if="stale" @click="wake">{{ t("refresh") }}</el-button>
  </main>

  <el-dialog v-model="renameOpen" :title="t('rename')" width="min(420px, calc(100vw - 24px))"><el-form @submit.prevent="saveRename"><el-form-item :label="t('name')"><el-input v-model="renameName" maxlength="64" /></el-form-item><div class="form-actions"><el-button @click="renameOpen=false">{{ t('cancel') }}</el-button><el-button native-type="submit" type="primary" :loading="renameBusy">{{ t('save') }}</el-button></div></el-form></el-dialog>
  <el-dialog v-model="editOpen" :title="t('editForward')" width="min(940px, calc(100vw - 24px))" @closed="cancelEdit"><ForwardForm v-model:port="editDraft.port" v-model:target="editDraft.target" title="" :editing="false" :busy="actionBusy || previewBusy" :available-ports="editPorts" :pool-enabled="poolEnabled" :port-hint="editHint" :port-valid="editValid" :presets="presets" :labels="{publicPort:t('publicPort'),lanAddress:t('lanAddress'),add:t('save'),create:t('newForward'),preset:t('preset')}" @preset="editPreset" @save="saveEdit"><template v-if="selected?.protocol === 'weroxy'"><el-form-item :label="t('dataPortPolicy')"><el-select v-model="editDraft.mode"><el-option value="shared" :label="t('shared')"/><el-option value="exclusive" :label="t('exclusive')"/></el-select></el-form-item><el-form-item :label="t('minPorts')"><el-input-number v-model="editDraft.min" :min="1" :max="editDraft.preferred"/></el-form-item><el-form-item :label="t('preferredPorts')"><el-input-number v-model="editDraft.preferred" :min="editDraft.min" :max="editDraft.max"/></el-form-item><el-form-item :label="t('maxPorts')"><el-input-number v-model="editDraft.max" :min="editDraft.preferred" :max="200"/></el-form-item></template></ForwardForm></el-dialog>
  <el-dialog :model-value="ask !== null" :title="ask?.title" width="min(460px, calc(100vw - 24px))" @close="ask = null">
    <p>{{ ask?.detail }}</p>
    <template #footer>
      <el-button @click="ask = null">{{ t("cancel") }}</el-button>
      <el-button type="primary" :disabled="actionBusy" @click="runConfirm">{{ t("confirm") }}</el-button>
    </template>
  </el-dialog>
 </div>
</template>
