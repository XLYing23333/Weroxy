<script setup lang="ts">
import { onUnmounted, ref } from "vue";
import { useRouter } from "vue-router";
import { useI18n } from "vue-i18n";
import { ApiError, api } from "../api";
import { reasonText } from "../i18n";

const router = useRouter();
const { t } = useI18n();
const username = ref("");
const password = ref("");
const error = ref("");
const submitting = ref(false);
let request: AbortController | null = null;
onUnmounted(() => {
  request?.abort();
  password.value = "";
});

async function submit() {
  if (submitting.value) return;
  submitting.value = true;
  request = new AbortController();
  error.value = "";
  try {
    await api("/api/v1/auth/login", {
      method: "POST",
      signal: request.signal,
      body: JSON.stringify({ username: username.value, password: password.value }),
    });
    password.value = "";
    await router.push("/");
  } catch (err) {
    if (request?.signal.aborted) return;
    error.value = t(reasonText(err instanceof ApiError ? err.code : "invalid"));
  } finally {
    password.value = "";
    submitting.value = false;
    request = null;
  }
}
</script>

<template>
  <el-form class="login" label-position="top" :aria-busy="submitting" @submit.prevent="submit">
    <img class="login-mark" src="/logo.png" alt="" width="72" height="72" />
    <h1 class="login-name">Weroxy</h1>
      <el-form-item :label="t('username')">
        <el-input v-model="username" :disabled="submitting" autocomplete="username" />
      </el-form-item>
      <el-form-item :label="t('password')">
        <el-input v-model="password" :disabled="submitting" type="password" autocomplete="current-password" show-password />
      </el-form-item>
      <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" />
      <el-button type="primary" native-type="submit" :loading="submitting" :disabled="submitting" style="margin-top: 12px; width: 100%">{{ t("login") }}</el-button>
    </el-form>
</template>
