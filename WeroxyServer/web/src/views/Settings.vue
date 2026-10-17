<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue";
import { useRouter } from "vue-router";
import { useI18n } from "vue-i18n";
import { ApiError, api, type Settings } from "../api";
import { reasonText } from "../i18n";
import { notify } from "../notice";
import { applyTheme } from "../theme";

const router = useRouter();
const { t, locale } = useI18n();
type UpdateInfo = {current_version:string;latest_version?:string;available:boolean;release_url?:string;checked_at?:string;status:string};
const updateInfo = ref<UpdateInfo | null>(null);
const updateBusy = ref(false);
async function checkUpdate(force=false) {
  if (updateBusy.value) return;
  updateBusy.value=true;
  try { updateInfo.value=await api<UpdateInfo>(force ? "/api/v1/update/check" : "/api/v1/update", {method: force ? "POST" : "GET", signal:loadRequest.signal}); }
  catch { updateInfo.value={current_version:updateInfo.value?.current_version || "—",available:false,status:"error"}; }
  finally { updateBusy.value=false; }
}
const settings = ref<Settings | null>(null);
const loading = ref(false);
const error = ref("");
const listEnabled = ref(false);
const listURL = window.location.origin + "/list";
const username = ref("");
const fileInput = ref<HTMLInputElement | null>(null);
function openList() { window.open(listURL,"_blank","noopener,noreferrer"); }
const listBusy = ref(false);
const mode = ref("shared");
const min = ref(1);
const preferred = ref(1);
const max = ref(4);
const current = ref("");
const next = ref("");
const again = ref("");
const passwordBusy = ref(false);
let passwordRequest: AbortController | null = null;
const backupFile = ref("");
const backupAction = ref<"create" | "restore" | null>(null);
const restoreFile = ref("");
const restoreConfirm = ref(false);
const uploadFile = ref<File | null>(null);

const loadRequest = new AbortController();
onUnmounted(() => loadRequest.abort());
async function load() {
  if (loading.value) return;
  loading.value = true;
  try {
    const [value, list, session] = await Promise.all([
      api<Settings>("/api/v1/settings", {signal:loadRequest.signal}),
      api<{enabled: boolean}>("/api/v1/settings/quick-list", {signal:loadRequest.signal}),
      api<{username:string}>("/api/v1/auth/session", {signal:loadRequest.signal}),
    ]);
    if (loadRequest.signal.aborted) return;
    settings.value = value;
    username.value = session.username;
    listEnabled.value = list.enabled;
    mode.value = value.defaults.mode;
    min.value = value.defaults.min;
    preferred.value = value.defaults.preferred;
    max.value = value.defaults.max;
    locale.value = value.locale;
    applyTheme(value.theme);
    error.value = "";
  } catch (err) {
    error.value = t(reasonText(err instanceof ApiError ? err.code : "invalid"));
  } finally { loading.value = false; }
}

let appearanceTask: Promise<void> = Promise.resolve();
let appearanceVersion = 0;
function saveAppearance() {
  if (!settings.value) return;
  const desired = {locale: settings.value.locale, theme: settings.value.theme};
  const version = ++appearanceVersion;
  // Serialize saves so an older request cannot become the persisted preference.
  appearanceTask = appearanceTask.then(async () => {
    try {
      const saved = await api<Pick<Settings, "locale" | "theme">>("/api/v1/settings", {
        method: "PUT", body: JSON.stringify(desired),
      });
      if (version !== appearanceVersion) return;
      locale.value = saved.locale;
      applyTheme(saved.theme);
    } catch (err) {
      notify({title: t("noticeAppearanceFailed"), message: t(reasonText(err instanceof ApiError ? err.code : "invalid")), tone: "error"});
    }
  });
  return appearanceTask;
}

async function saveList(value: boolean) {
  if (listBusy.value) return;
  listBusy.value = true;
  try {
    const result = await api<{enabled:boolean}>("/api/v1/settings/quick-list", {method:"PUT",body:JSON.stringify({enabled:value})});
    listEnabled.value = result.enabled;
    notify({title:t("quickList"),message:t("saved"),tone:"success"});
  } catch(err) {
    listEnabled.value = !value;
    notify({title:t("quickList"),message:t(reasonText(err instanceof ApiError ? err.code : "invalid")),tone:"error"});
  } finally { listBusy.value = false; }
}

async function saveDefaults() {
  try {
    await api("/api/v1/settings/defaults", {method:"PUT",body:JSON.stringify({mode:mode.value,min:Number(min.value),preferred:Number(preferred.value),max:Number(max.value)})});
    notify({ title:t("noticeDefaultsSaved"), tone:"success" });
    await load();
  } catch(err) {
    notify({title:t("noticeDefaultsFailed"),message:t(reasonText(err instanceof ApiError ? err.code : "invalid")),tone:"error"});
  }
}

async function changePassword() {
  if (passwordBusy.value) return;
  if (next.value !== again.value) { notify({title:t("noticePasswordMismatch"),tone:"error"});return; }
  passwordBusy.value = true;
  passwordRequest = new AbortController();
  try {
    await api("/api/v1/auth/password", {method:"POST",signal:passwordRequest.signal,body:JSON.stringify({current:current.value,password:next.value,confirm:again.value})});
    notify({title:t("noticePasswordSaved"),tone:"success"});
    router.push("/login");
  } catch(err) {
    if (!passwordRequest?.signal.aborted) notify({title:t("noticePasswordFailed"),message:t(reasonText(err instanceof ApiError ? err.code : "invalid")),tone:"error"});
  } finally {
    current.value = ""; next.value = ""; again.value = "";
    passwordBusy.value = false; passwordRequest = null;
  }
}

async function runBackup() {
  if (backupAction.value) return;
  backupAction.value = "create";
  try {
    const saved=await api<{file:string}>("/api/v1/backup",{method:"POST",body:"{}"});
    backupFile.value=saved.file;
    notify({title:t("noticeBackupSaved"),message:saved.file,tone:"success"});
  } catch(err) {notify({title:t("noticeBackupFailed"),message:t(reasonText(err instanceof ApiError ? err.code : "invalid")),tone:"error"});}
  finally {backupAction.value=null;}
}
function downloadBackup() {
  if (backupFile.value) window.location.href="/api/v1/backup/download?file="+encodeURIComponent(backupFile.value);
}
function pickRestore(event:Event) {
  if (backupAction.value) return;
  const input=event.target as HTMLInputElement;
  if(!input.files?.length) return;
  uploadFile.value=input.files[0];
  restoreFile.value=uploadFile.value?.name??"";
  restoreConfirm.value=false;
}
async function restoreBackup() {
  if (backupAction.value || !uploadFile.value || !restoreConfirm.value) return;
  backupAction.value="restore";
  try {
    const body=new FormData();body.append("file",uploadFile.value);body.append("confirm","true");
    await api("/api/v1/backup/upload",{method:"POST",body});
    router.push("/login");
  } catch(err) {notify({title:t("noticeRestoreFailed"),message:t(reasonText(err instanceof ApiError ? err.code : "invalid")),tone:"error"});}
  finally {backupAction.value=null;restoreConfirm.value=false;}
}

onMounted(() => {void load(); void checkUpdate();});
onUnmounted(() => {passwordRequest?.abort();current.value="";next.value="";again.value="";});
</script>

<template>
  <main class="page" v-if="!settings" :aria-busy="loading">
    <p v-if="loading">{{ t("loading") }}</p>
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <el-button v-if="error" @click="load">{{ t("refresh") }}</el-button>
  </main>
  <main class="page settings-grid" v-else>
    <div class="settings-col">
      <section class="form-block">
        <h3>{{ t("settings") }}</h3>
        <div class="option-row"><span>{{ t("language") }}</span><el-radio-group v-model="settings.locale" @change="saveAppearance"><el-radio-button value="zh">中文</el-radio-button><el-radio-button value="en">English</el-radio-button></el-radio-group></div>
        <div class="option-row"><span>{{ t("theme") }}</span><el-radio-group v-model="settings.theme" @change="saveAppearance"><el-radio-button value="system">{{ t("system") }}</el-radio-button><el-radio-button value="light">{{ t("light") }}</el-radio-button><el-radio-button value="dark">{{ t("dark") }}</el-radio-button></el-radio-group></div>
      </section>
      <section class="form-block">
        <h3>{{ t("quickList") }}</h3>
        <p class="reason">{{ t("quickListPublicHint") }}</p>
        <div class="option-row"><span>{{ t("state") }}</span><el-switch :model-value="listEnabled" :loading="listBusy" @change="saveList" /></div>
        <div v-if="listEnabled" class="quick-list-url"><code>{{ listURL }}</code><el-button @click="openList">{{ t("openList") }}</el-button></div>
      </section>

      <section class="form-block">
        <h3>{{ t("changePassword") }}</h3>
        <el-form label-position="top" @submit.prevent="changePassword">
          <p class="account-name">{{ t("username") }}：<strong>{{ username }}</strong></p>
          <el-form-item :label="t('currentPassword')"><el-input v-model="current" :disabled="passwordBusy" type="password" autocomplete="current-password" show-password /></el-form-item>
          <el-form-item :label="t('newPassword')"><el-input v-model="next" :disabled="passwordBusy" type="password" autocomplete="new-password" show-password /></el-form-item>
          <el-form-item :label="t('repeatPassword')"><el-input v-model="again" :disabled="passwordBusy" type="password" autocomplete="new-password" show-password /></el-form-item>
          <el-button type="primary" native-type="submit" :loading="passwordBusy">{{ t("save") }}</el-button>
        </el-form>
      </section>

    </div>
    <div class="settings-col">
      <section class="form-block update-card">
        <h3>{{ t("softwareUpdate") }}</h3>
        <p>{{ t("currentVersion") }}: {{ updateInfo?.current_version || '—' }}</p>
        <p v-if="updateInfo?.latest_version">{{ t("latestVersion") }}: {{ updateInfo.latest_version }}</p>
        <p role="status">{{ updateBusy ? t('checkingUpdate') : updateInfo?.status === 'error' ? t('updateUnavailable') : updateInfo?.available ? t('updateAvailable') : updateInfo?.status === 'ok' ? t(updateInfo.latest_version !== updateInfo.current_version ? 'newerThanRelease' : 'upToDate') : '—' }}</p>
        <p v-if="updateInfo?.checked_at" class="reason">{{ t('lastChecked') }}: {{ new Date(updateInfo.checked_at).toLocaleString() }}</p>
        <div class="inline-row"><el-button :loading="updateBusy" @click="checkUpdate(true)">{{ t('checkUpdate') }}</el-button><a v-if="updateInfo?.release_url" :href="updateInfo.release_url" target="_blank" rel="noopener noreferrer">{{ t('viewRelease') }}</a></div>
      </section>
      <section class="form-block">
        <h3>{{ t("forwardDefaults") }}</h3>
        <div class="option-row"><span>{{ t("mode") }}</span><el-radio-group v-model="mode"><el-radio-button value="shared">{{ t("shared") }}</el-radio-button><el-radio-button value="exclusive">{{ t("exclusive") }}</el-radio-button></el-radio-group></div>
        <div class="split default-capacities"><el-form-item :label="t('minPorts')"><el-input v-model.number="min" /></el-form-item><el-form-item :label="t('preferredPorts')"><el-input v-model.number="preferred" /></el-form-item><el-form-item :label="t('maxPorts')"><el-input v-model.number="max" /></el-form-item></div>
        <el-button type="primary" @click="saveDefaults">{{ t("save") }}</el-button>
      </section>
      <section class="form-block">
        <h3>{{ t("hostPublication") }}</h3>
        <p>{{ t(`publication_${settings.publication?.status ?? 'unverified'}`) }} · {{ settings.publication?.published_count ?? 0 }}/{{ settings.publication?.listener_count ?? 0 }}</p>
        <p v-if="settings.publication?.missing_ports?.length" class="reason">{{ t("publicationMissing") }}: {{ settings.publication.missing_ports.join(", ") }}</p>
        <p class="reason">{{ t("forwardPool") }}: {{ settings.pool.forward_first }}–{{ settings.pool.forward_last }} · {{ t("channelPool") }}: {{ settings.pool.data_first }}–{{ settings.pool.data_last }}</p>
      </section>
      <section class="form-block">
        <h3>{{ t("backup") }}</h3>
        <p class="reason">{{ t("restoreImpact") }}</p>
        <div class="inline-row"><el-input v-model="backupFile" readonly :placeholder="t('file')" /><el-button :disabled="!backupFile || backupAction !== null" @click="downloadBackup">{{ t("download") }}</el-button><el-button type="primary" :loading="backupAction === 'create'" :disabled="backupAction !== null" @click="runBackup">{{ t("backup") }}</el-button></div>
        <div class="inline-row"><el-button :disabled="backupAction !== null" @click="fileInput?.click()">{{ t("chooseFile") }}</el-button><input ref="fileInput" hidden type="file" accept=".db,application/vnd.sqlite3,application/x-sqlite3" :disabled="backupAction !== null" @change="pickRestore" /><span class="reason">{{ restoreFile }}</span><el-checkbox v-model="restoreConfirm">{{ t("confirmRestore") }}</el-checkbox><el-button :loading="backupAction === 'restore'" :disabled="!uploadFile || !restoreConfirm || backupAction !== null" @click="restoreBackup">{{ t("restore") }}</el-button></div>
      </section>
    </div>
  </main>
</template>
