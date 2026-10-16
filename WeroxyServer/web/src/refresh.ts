import { ref } from "vue";

export const refreshTick = ref(0);

export function refreshViews() {
  refreshTick.value += 1;
}
