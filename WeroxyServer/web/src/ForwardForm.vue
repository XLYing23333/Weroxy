<script setup lang="ts">
import { computed, nextTick, ref } from "vue";

const props = defineProps<{
  title: string;
  editing: boolean;
  busy?: boolean;
  availablePorts: string[];
  poolEnabled: boolean;
  portHint: string;
  portValid: boolean;
  presets: { id: string; label: string; port: number }[];
  labels: {
    publicPort: string;
    lanAddress: string;
    add: string;
    create: string;
    preset: string;
  };
}>();

const port = defineModel<string>("port", { required: true });
const target = defineModel<string>("target", { required: true });
function splitTarget(value: string) {
  const index = value.lastIndexOf(":");
  if (index < 0) return { host: value, port: "" };
  const host = value.slice(0, index);
  return { host: host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host, port: value.slice(index + 1) };
}

function joinTarget(host: string, port: string) {
  const clean = host.trim().replace(/^\[|\]$/g, "");
  return `${clean.includes(":") ? `[${clean}]` : clean}:${port}`;
}

const lanHost = computed({
  get: () => splitTarget(target.value).host,
  set: (host: string) => { target.value = joinTarget(host, splitTarget(target.value).port); },
});
const lanPort = computed({
  get: () => splitTarget(target.value).port,
  set: (port: string) => { target.value = joinTarget(splitTarget(target.value).host, port.replace(/\D/g, "")); },
});

const emit = defineEmits<{
  preset: [port: number];
  save: [];
  create: [];
}>();

const presetOpen = ref(false);

function pickPreset(value: number) {
  emit("preset", value);
  nextTick(() => {
    presetOpen.value = false;
  });
}
</script>

<template>
  <section class="form-block forward-block">
    <div v-if="title" class="form-head">
      <h3>{{ title }}</h3>
      <el-button v-if="editing" native-type="button" @click="emit('create')">{{ labels.create }}</el-button>
    </div>
    <el-form class="compact-forward" label-position="top" :disabled="busy" @submit.prevent="!busy && emit('save')">
      <el-dialog v-model="presetOpen" :title="labels.preset" width="min(420px, calc(100vw - 24px))" append-to-body>
        <div class="presets">
          <el-button v-for="item in props.presets" :key="item.id" native-type="button" @click.stop="pickPreset(item.port)"><span>{{ item.label }}</span><code>{{ item.port }}</code></el-button>
        </div>
      </el-dialog>
      <div class="forward-address-grid">
        <el-form-item :label="labels.publicPort">
          <el-select v-if="poolEnabled" v-model="port" filterable allow-create default-first-option :placeholder="labels.publicPort" class="full-width">
            <el-option v-for="item in availablePorts" :key="item" :label="item" :value="item" />
          </el-select>
          <el-input v-else v-model="port" inputmode="numeric" maxlength="5" />
        </el-form-item>
        <span class="forward-arrow" aria-hidden="true">→</span>
        <el-form-item :label="labels.lanAddress">
          <div class="forward-target">
            <el-input v-model="lanHost" :aria-label="labels.lanAddress" placeholder="127.0.0.1" />
            <span aria-hidden="true">:</span>
            <el-input v-model="lanPort" inputmode="numeric" maxlength="5" :aria-label="labels.lanAddress + ' port'" class="target-port" />
          </div>
        </el-form-item>
        <div class="form-actions forward-actions"><el-button native-type="button" @click="presetOpen = true">{{ labels.preset }}</el-button><el-button native-type="submit" type="primary" :loading="busy" :disabled="!portValid">{{ labels.add }}</el-button></div>
      </div>
      <div class="forward-policy-row"><div class="forward-fields"><slot /></div>
      <p class="forward-port-hint" :class="{ 'is-error': !portValid }">{{ portHint }}</p></div>

    </el-form>
  </section>
</template>

<style scoped>
.forward-block {padding:12px;min-width:0;}
.form-head {margin-bottom:6px;}
.compact-forward {display:flex;flex-direction:column;gap:6px;min-width:0;}
.compact-forward :deep(.el-form-item) {margin:0;min-width:0;}
.compact-forward :deep(.el-form-item__label) {margin-bottom:4px;line-height:18px;}
.forward-address-grid {display:grid;grid-template-columns:minmax(100px,.7fr) 16px minmax(220px,1.5fr) auto;gap:8px;align-items:end;}
.forward-address-grid :deep(.el-form-item__content) {display:block;}
.forward-arrow {padding-bottom:7px;text-align:center;}
.full-width {width:100%;}
.forward-target {display:flex;align-items:center;gap:6px;min-width:0;}
.forward-target .el-input:first-child {flex:1;min-width:0;}
.forward-target .target-port {width:84px;flex:0 0 84px;}
.forward-policy-row {display:flex;align-items:end;gap:12px;flex-wrap:wrap;}
.forward-fields {flex:1 1 460px;display:grid;grid-template-columns:1.15fr repeat(3,minmax(0,1fr));gap:8px;max-width:620px;}
.forward-fields:empty {display:none;}
.forward-fields :deep(.el-input-number),.forward-fields :deep(.el-select) {width:100%;}
.forward-port-hint {margin:0;color:var(--el-text-color-secondary);font-size:12px;line-height:1.4;}
.forward-port-hint.is-error {color:var(--el-color-danger);}
.forward-actions {display:flex;gap:8px;margin:0;flex-wrap:nowrap;}
.forward-actions :deep(.el-button + .el-button) {margin-left:0;}
.presets {display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;}
.presets :deep(.el-button) {margin:0;min-width:0;height:48px;padding:8px;}
.presets :deep(.el-button > span) {width:100%;display:flex;flex-direction:column;align-items:center;gap:4px;}
.presets code {font-size:11px;color:var(--el-text-color-secondary);}
@media(max-width:700px){.forward-address-grid{grid-template-columns:minmax(90px,.6fr) 12px minmax(170px,1.4fr);}.forward-actions{grid-column:3;justify-content:flex-end;}.forward-fields{grid-template-columns:repeat(2,minmax(0,1fr));}}
@media(max-width:480px){.forward-address-grid{grid-template-columns:minmax(0,1fr);}.forward-arrow{display:none;}.forward-actions{grid-column:1;}.presets{grid-template-columns:repeat(2,minmax(0,1fr));}.forward-target .target-port{width:72px;flex-basis:72px;}}
</style>
