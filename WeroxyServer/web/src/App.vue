<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { useI18n } from "vue-i18n";
import { api, type Device, type Settings } from "./api";
import { usePoll } from "./poll";
import NoticeHost from "./NoticeHost.vue";
import { failedPage } from "./router";
import { refreshTick } from "./refresh";
import { applyTheme, currentTheme, watchSystemTheme } from "./theme";

function reloadPage() {
  if (failedPage.value) window.location.assign(router.resolve(failedPage.value).href);
}

const route = useRoute();
const router = useRouter();
const { t, locale } = useI18n();
const theme = currentTheme;
const devices = ref<Device[]>([]);
const navDevices = computed(() =>
  [...devices.value].sort((a, b) => {
    const rank = (value: string) => (value === "weroxy" ? 0 : 1);
    return rank(a.protocol) - rank(b.protocol) || a.name.localeCompare(b.name);
  }),
);
const signedIn = computed(() => route.matched.length > 0 && route.path !== "/login" && route.path !== "/setup" && !route.params.token);
const configOpen = ref(route.path.startsWith("/devices"));

watch(signedIn, async (value) => {
  if(!value) return;
  try {const settings=await api<Settings>("/api/v1/settings");locale.value=settings.locale;theme.value=settings.theme;applyTheme(settings.theme);await loadNav();} catch {applyTheme("system");}
});

watch(() => route.path, (path) => {
  configOpen.value = path.startsWith("/devices");
});

watch(refreshTick, () => {
  void loadNav();
});

function toggleConfig() {
  configOpen.value = true;
  if (route.path !== "/devices") router.push("/devices");
}

async function loadNav() {
  if (!signedIn.value) return;
  const list = await api<{ devices: Device[] }>("/api/v1/devices");
  devices.value = list.devices;
}

onMounted(async () => {
  watchSystemTheme(() => theme.value);
  if (!signedIn.value) return;
  try {
    const settings = await api<Settings>("/api/v1/settings");
    locale.value = settings.locale;
    theme.value = settings.theme;
    applyTheme(settings.theme);
  } catch {
    applyTheme("system");
  }
});

usePoll(loadNav);

async function logout() {
  await api("/api/v1/auth/logout", { method: "POST" });
  router.push("/login");
}
</script>

<template>
  <div class="shell">
    <aside v-if="signedIn" class="side">
      <router-link class="brand" to="/" :aria-label="t('dashboard')">
        <img src="/logo.png" alt="Weroxy" />
        <strong>Weroxy</strong>
      </router-link>
      <nav>
        <router-link to="/">
          <svg viewBox="0 0 16 16" aria-hidden="true">
            <path fill="currentColor" d="M8 4a.5.5 0 0 1 .5.5V6a.5.5 0 0 1-1 0V4.5A.5.5 0 0 1 8 4M3.732 5.732a.5.5 0 0 1 .707 0l.915.914a.5.5 0 1 1-.708.708l-.914-.915a.5.5 0 0 1 0-.707M2 10a.5.5 0 0 1 .5-.5h1.586a.5.5 0 0 1 0 1H2.5A.5.5 0 0 1 2 10m9.5 0a.5.5 0 0 1 .5-.5h1.5a.5.5 0 0 1 0 1H12a.5.5 0 0 1-.5-.5m.754-4.246a.39.39 0 0 0-.527-.02L7.547 9.31a.91.91 0 1 0 1.302 1.258l3.434-4.297a.39.39 0 0 0-.029-.518z" />
            <path fill="currentColor" fill-rule="evenodd" d="M0 10a8 8 0 1 1 15.547 2.661c-.442 1.253-1.845 1.602-2.932 1.25C11.309 13.488 9.475 13 8 13c-1.474 0-3.31.488-4.615.911-1.087.352-2.49.003-2.932-1.25A8 8 0 0 1 0 10m8-7a7 7 0 0 0-6.603 9.329c.203.575.923.876 1.68.63C4.397 12.533 6.358 12 8 12s3.604.532 4.923.96c.757.245 1.477-.056 1.68-.631A7 7 0 0 0 8 3" />
          </svg>
          <span>{{ t("dashboard") }}</span>
        </router-link>
        <button type="button" class="linkish" :class="{ 'router-link-active': route.path.startsWith('/devices') }" @click="toggleConfig">
          <svg viewBox="0 0 16 16" aria-hidden="true">
            <path fill="currentColor" fill-rule="evenodd" d="M11.5 2a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3M9.05 3a2.5 2.5 0 0 1 4.9 0H16v1h-2.05a2.5 2.5 0 0 1-4.9 0H0V3zM4.5 7a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3M2.05 8a2.5 2.5 0 0 1 4.9 0H16v1H6.95a2.5 2.5 0 0 1-4.9 0H0V8zm9.45 4a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3m-2.45 1a2.5 2.5 0 0 1 4.9 0H16v1h-2.05a2.5 2.5 0 0 1-4.9 0H0v-1z" />
          </svg>
          <span>{{ t("devices") }}</span>
        </button>
        <div class="subs" :class="{ open: configOpen }">
          <div>
            <router-link
              v-for="item in navDevices"
              :key="item.protocol + item.name"
              class="sub"
              :class="{ active: route.params.name === item.name }"
              :to="'/devices/' + item.name"
            >
              <svg v-if="item.protocol === 'weroxy'" viewBox="0 0 16 16" aria-hidden="true">
                <path fill="currentColor" d="M5.525 3.025a3.5 3.5 0 0 1 4.95 0 .5.5 0 1 0 .707-.707 4.5 4.5 0 0 0-6.364 0 .5.5 0 0 0 .707.707" />
                <path fill="currentColor" d="M6.94 4.44a1.5 1.5 0 0 1 2.12 0 .5.5 0 0 0 .708-.708 2.5 2.5 0 0 0-3.536 0 .5.5 0 0 0 .707.707M2.5 11a.5.5 0 1 1 0-1 .5.5 0 0 1 0 1m4.5-.5a.5.5 0 1 0 1 0 .5.5 0 0 0-1 0m2.5.5a.5.5 0 1 1 0-1 .5.5 0 0 1 0 1m1.5-.5a.5.5 0 1 0 1 0 .5.5 0 0 0-1 0m2 0a.5.5 0 1 0 1 0 .5.5 0 0 0-1 0" />
                <path fill="currentColor" d="M2.974 2.342a.5.5 0 1 0-.948.316L3.806 8H1.5A1.5 1.5 0 0 0 0 9.5v2A1.5 1.5 0 0 0 1.5 13H2a.5.5 0 0 0 .5.5h2A.5.5 0 0 0 5 13h6a.5.5 0 0 0 .5.5h2a.5.5 0 0 0 .5-.5h.5a1.5 1.5 0 0 0 1.5-1.5v-2A1.5 1.5 0 0 0 14.5 8h-2.306l1.78-5.342a.5.5 0 1 0-.948-.316L11.14 8H4.86zM14.5 9a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-.5.5h-13a.5.5 0 0 1-.5-.5v-2a.5.5 0 0 1 .5-.5z" />
                <path fill="currentColor" d="M8.5 2.5a.5.5 0 1 1-1 0 .5.5 0 0 1 1 0" />
              </svg>
              <svg v-else viewBox="0 0 16 16" aria-hidden="true">
                <path fill="currentColor" d="M4.5 5a.5.5 0 1 0 0-1 .5.5 0 0 0 0 1M3 4.5a.5.5 0 1 1-1 0 .5.5 0 0 1 1 0" />
                <path fill="currentColor" d="M0 4a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v1a2 2 0 0 1-2 2H8.5v3a1.5 1.5 0 0 1 1.5 1.5h5.5a.5.5 0 0 1 0 1H10A1.5 1.5 0 0 1 8.5 14h-1A1.5 1.5 0 0 1 6 12.5H.5a.5.5 0 0 1 0-1H6A1.5 1.5 0 0 1 7.5 10V7H2a2 2 0 0 1-2-2zm1 0v1a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V4a1 1 0 0 0-1-1H2a1 1 0 0 0-1 1m6 7.5v1a.5.5 0 0 0 .5.5h1a.5.5 0 0 0 .5-.5v-1a.5.5 0 0 0-.5-.5h-1a.5.5 0 0 0-.5.5" />
              </svg>
              <span>{{ item.name }}</span>
            </router-link>
          </div>
        </div>
        <router-link to="/settings">
          <svg viewBox="0 0 16 16" aria-hidden="true">
            <path fill="currentColor" d="M8 4.754a3.246 3.246 0 1 0 0 6.492 3.246 3.246 0 0 0 0-6.492M5.754 8a2.246 2.246 0 1 1 4.492 0 2.246 2.246 0 0 1-4.492 0" />
            <path fill="currentColor" d="M9.796 1.343c-.527-1.79-3.065-1.79-3.592 0l-.094.319a.873.873 0 0 1-1.255.52l-.292-.16c-1.64-.892-3.433.902-2.54 2.541l.159.292a.873.873 0 0 1-.52 1.255l-.319.094c-1.79.527-1.79 3.065 0 3.592l.319.094a.873.873 0 0 1 .52 1.255l-.16.292c-.892 1.64.901 3.434 2.541 2.54l.292-.159a.873.873 0 0 1 1.255.52l.094.319c.527 1.79 3.065 1.79 3.592 0l.094-.319a.873.873 0 0 1 1.255-.52l.292.16c1.64.893 3.434-.902 2.54-2.541l-.159-.292a.873.873 0 0 1 .52-1.255l.319-.094c1.79-.527 1.79-3.065 0-3.592l-.319-.094a.873.873 0 0 1-.52-1.255l.16-.292c.893-1.64-.902-3.433-2.541-2.54l-.292.159a.873.873 0 0 1-1.255-.52zm-2.633.283c.246-.835 1.428-.835 1.674 0l.094.319a1.873 1.873 0 0 0 2.693 1.115l.291-.16c.764-.415 1.6.42 1.184 1.185l-.159.292a1.873 1.873 0 0 0 1.116 2.692l.318.094c.835.246.835 1.428 0 1.674l-.319.094a1.873 1.873 0 0 0-1.115 2.693l.16.291c.415.764-.42 1.6-1.185 1.184l-.291-.159a1.873 1.873 0 0 0-2.693 1.116l-.094.318c-.246.835-1.428.835-1.674 0l-.094-.319a1.873 1.873 0 0 0-2.692-1.115l-.292.16c-.764.415-1.6-.42-1.184-1.185l.159-.291A1.873 1.873 0 0 0 1.945 8.93l-.319-.094c-.835-.246-.835-1.428 0-1.674l.319-.094A1.873 1.873 0 0 0 3.06 4.377l-.16-.292c-.415-.764.42-1.6 1.185-1.184l.292.159a1.873 1.873 0 0 0 2.692-1.115z" />
          </svg>
          <span>{{ t("settings") }}</span>
        </router-link>
      </nav>
      <div class="side-foot">
        <span>© 2026 15Digital Company</span>
        <button class="logout" type="button" :aria-label="t('logout')" :title="t('logout')" @click="logout">
          <svg viewBox="0 0 16 16" aria-hidden="true">
            <path fill="currentColor" d="M10 12.5a.5.5 0 0 1-.5.5h-8a.5.5 0 0 1-.5-.5v-9a.5.5 0 0 1 .5-.5h8a.5.5 0 0 1 .5.5v2a.5.5 0 0 0 1 0v-2A1.5 1.5 0 0 0 9.5 2h-8A1.5 1.5 0 0 0 0 3.5v9A1.5 1.5 0 0 0 1.5 14h8a1.5 1.5 0 0 0 1.5-1.5v-2a.5.5 0 0 0-1 0z" />
            <path fill="currentColor" d="M15.854 8.354a.5.5 0 0 0 0-.708l-3-3a.5.5 0 0 0-.708.708L14.293 7.5H5.5a.5.5 0 0 0 0 1h8.793l-2.147 2.146a.5.5 0 0 0 .708.708z" />
          </svg>
        </button>
      </div>
    </aside>
    <div v-if="!signedIn" class="public-appearance">
      <el-select v-model="locale" aria-label="Language" size="small"><el-option label="中文" value="zh"/><el-option label="English" value="en"/></el-select>
      <el-select v-model="theme" :aria-label="t('theme')" size="small" @change="applyTheme(theme)"><el-option :label="t('system')" value="system"/><el-option :label="t('light')" value="light"/><el-option :label="t('dark')" value="dark"/></el-select>
    </div>
    <div class="content">
      <section v-if="failedPage" class="page-view" role="alert">
        <h2>{{ t("pageLoadFailed") }}</h2>
        <p>{{ t("pageLoadFailedHint") }}</p>
        <button type="button" @click="reloadPage">{{ t("pageReload") }}</button>
      </section>
      <router-view v-else v-slot="{ Component }">
        <transition name="page-switch" mode="out-in"><component :is="Component" :key="route.fullPath" class="page-view" /></transition>
      </router-view>
    </div>
    <NoticeHost />
  </div>
</template>
