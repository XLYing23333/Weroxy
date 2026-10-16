import { ref, watch } from "vue";

export const currentTheme = ref<"system" | "light" | "dark">("system");

export function applyTheme(theme: "system" | "light" | "dark") {
  currentTheme.value = theme;
  const dark =
    theme === "dark" ||
    (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.classList.toggle("dark", dark);
  document.documentElement.dataset.theme = theme;
}

export function watchSystemTheme(current: () => "system" | "light" | "dark") {
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  const update = () => applyTheme(current());
  media.addEventListener("change", update);
  watch(current, update);
}
