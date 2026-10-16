import { ref } from "vue";

export type NoticeTone = "success" | "info" | "warning" | "error";

export type Notice = {
  id: number;
  title: string;
  message: string;
  tone: NoticeTone;
  duration: number;
};

export const notices = ref<Notice[]>([]);
let seq = 0;
const timers = new Map<number, number>();
const maxNotices = 6;

export function notify(input: { title: string; message?: string; tone?: NoticeTone; duration?: number }) {
  const id = ++seq;
  const duration = Math.min(30000, Math.max(100, input.duration ?? 3000));
  const item: Notice = {
    id,
    title: input.title,
    message: input.message ?? "",
    tone: input.tone ?? "info",
    duration,
  };
  while (notices.value.length >= maxNotices) dismiss(notices.value[0].id);
  notices.value = [...notices.value, item];
  timers.set(id, window.setTimeout(() => dismiss(id), duration));
}

export function dismiss(id: number) {
  const timer = timers.get(id);
  if (timer !== undefined) window.clearTimeout(timer);
  timers.delete(id);
  notices.value = notices.value.filter((item) => item.id !== id);
}
