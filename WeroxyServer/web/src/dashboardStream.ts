import { onMounted, onUnmounted } from "vue";
import { usePoll } from "./poll";
import type { Dashboard } from "./api";

export function useDashboardStream(load: (signal?: AbortSignal) => Promise<void>, receive: (item: Dashboard) => void, interval: () => number) {
  let source: EventSource | null = null;
  let connected = false;
  let lastFrame = 0;
  const state = usePoll(async (signal) => {
    if (connected && Date.now() - lastFrame > Math.max(10000, interval() * 2 + 5000)) connected = false;
    if (!connected) await load(signal);
  }, interval);
  function close() {
    connected = false;
    source?.close();
    source = null;
  }
  function open() {
    close();
    if (document.visibilityState === "hidden") return;
    source = new EventSource("/api/v1/dashboard/events");
    source.addEventListener("dashboard", (event) => {
      try {
        const item = JSON.parse((event as MessageEvent).data) as Dashboard;
        if (!Array.isArray(item.devices) || !Number.isFinite(item.refresh_sec)) throw new Error("invalid snapshot");
        receive(item);
        connected = true;
        lastFrame = Date.now();
        state.loading.value = false;
        state.stale.value = false;
      } catch {
        connected = false;
        state.stale.value = true;
      }
    });
    source.onerror = () => { connected = false; state.stale.value = true; };
  }
  onMounted(() => { open(); document.addEventListener("visibilitychange", open); });
  onUnmounted(() => { close(); document.removeEventListener("visibilitychange", open); });
  return state;
}
