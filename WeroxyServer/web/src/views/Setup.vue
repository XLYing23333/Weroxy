<script setup lang="ts">
import { onUnmounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { useI18n } from "vue-i18n";
import { api, ApiError } from "../api";
import { reasonText } from "../i18n";
const { t }=useI18n(), route=useRoute(), router=useRouter();
const username=ref(""), password=ref(""), confirm=ref(""), busy=ref(false), error=ref("");
let request:AbortController|null=null;
async function submit(){
 if(busy.value)return;busy.value=true;error.value="";request=new AbortController();
 try {await api("/api/v1/setup",{method:"POST",signal:request.signal,headers:{"X-Weroxy-Setup":String(route.params.token)},body:JSON.stringify({username:username.value,password:password.value,confirm:confirm.value})});await router.replace("/login");}
 catch(err){if(!request.signal.aborted)error.value=t(reasonText(err instanceof ApiError?err.code:"invalid"));}
 finally{password.value="";confirm.value="";busy.value=false;request=null;}
}
onUnmounted(()=>{request?.abort();password.value="";confirm.value="";});
</script>
<template>
 <el-form class="login" label-position="top" @submit.prevent="submit">
  <img class="login-mark" src="/logo.png" alt="" width="72" height="72"/><h1>{{ t("setup") }}</h1>
  <template v-if="route.params.token">
   <p class="reason">{{ t("setupAccountHint") }}</p>
   <el-form-item :label="t('username')"><el-input v-model="username" :disabled="busy" maxlength="64" autocomplete="username" /></el-form-item>
   <el-form-item :label="t('password')"><el-input v-model="password" :disabled="busy" type="password" autocomplete="new-password" show-password /></el-form-item>
   <el-form-item :label="t('repeatPassword')"><el-input v-model="confirm" :disabled="busy" type="password" autocomplete="new-password" show-password /></el-form-item>
   <el-alert v-if="error" :title="error" type="error" :closable="false"/>
   <el-button type="primary" native-type="submit" :loading="busy" class="setup-submit">{{ t("save") }}</el-button>
  </template>
  <p v-else>{{ t("setupConsole") }}</p>
 </el-form>
</template>
