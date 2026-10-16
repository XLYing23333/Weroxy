import { onMounted, onUnmounted, ref } from "vue";

export function usePoll(run: (signal?: AbortSignal) => Promise<void>, interval: () => number = () => 5000) {
  const loading = ref(true);
  const stale = ref(false);
  let timer = 0;
  let stopped = false;
  let failures = 0;
  let running: Promise<void> | null = null;
  let controller: AbortController | null = null;

  function tick(): Promise<void> {
    if (stopped) return Promise.resolve();
    if (running) return running;
    controller = new AbortController();
    running = (async () => {
      try {
        await run(controller?.signal);
        failures = 0;
        stale.value = false;
      } catch {
        failures += 1;
        stale.value = true;
      } finally {
        loading.value = false;
      }
    })().finally(() => { running = null; });
    return running;
  }

  function arm() {
    if (stopped) return;
    window.clearTimeout(timer);
    const hidden = document.visibilityState === "hidden";
    const configured = interval();
    const normal = Number.isFinite(configured) ? Math.max(1000, Math.min(60000, configured)) : 5000;
    const base = hidden ? Math.max(30000, normal) : normal;
    const delay = failures > 0 ? Math.min(Math.max(30000, base), base * failures) : base;
    timer = window.setTimeout(async () => {
      await tick();
      arm();
    }, delay);
  }

  function wake() {
    window.clearTimeout(timer);
    void tick().finally(arm);
  }

  onMounted(() => {
    void tick().finally(arm);
    document.addEventListener("visibilitychange", wake);
  });
  onUnmounted(() => {
    stopped = true;
    controller?.abort();
    window.clearTimeout(timer);
    document.removeEventListener("visibilitychange", wake);
  });

  return { loading, stale, wake };
}
