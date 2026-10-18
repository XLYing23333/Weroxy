<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, shallowRef, watch } from "vue";
import { useI18n } from "vue-i18n";
import * as echarts from "echarts/core";
import { BarChart, LineChart } from "echarts/charts";
import { GridComponent, LegendComponent, TooltipComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import { api, type Dashboard, type StatusDevice, type StatusPoint } from "../api";
import { formatBytes, formatClock, formatCount as compact } from "../format";
import { statusBlocks as blocks, type StatusBlock } from "../statusHistory";
import { useDashboardStream } from "../dashboardStream";

echarts.use([LineChart, BarChart, GridComponent, LegendComponent, TooltipComponent, CanvasRenderer]);

const slots = 36;
const palette = ["#8b5a2b", "#3f8f62", "#c4a574", "#6b5344", "#d7c4a3", "#a67c52"];
const { t } = useI18n();
const data = ref<Dashboard | null>(null);
const trafficEl = ref<HTMLElement | null>(null);
const deviceEl = ref<HTMLElement | null>(null);
const traffic = shallowRef<echarts.ECharts | null>(null);
const deviceChart = shallowRef<echarts.ECharts | null>(null);
const detailDropped = computed(() => (data.value?.connection_persistence?.dropped ?? 0) > 0);
const failureTotal = computed(() => Object.values(data.value?.failures ?? {}).reduce((sum, value) => sum + value, 0));
const board = computed(() =>
  [...(data.value?.devices ?? [])].sort((a, b) => {
    const rank = (value: string) => (value === "weroxy" ? 0 : 1);
    return rank(a.protocol) - rank(b.protocol) || a.name.localeCompare(b.name);
  }),
);
function statusTone(online: boolean, sessions: number, known = true) {
  if (!known) return "unknown";
  if (!online) return "offline";
  if (sessions <= 3) return "green";
  if (sessions <= 10) return "yellow";
  return "orange";
}

function uptime(history: StatusPoint[]) {
 const items=blocks(history), seen=items.reduce((n,p)=>n+p.observedSeconds,0);
 if(!seen) return "";const value=items.reduce((n,p)=>n+p.onlineSeconds,0)/seen*100;
 return `${value===100?"100":value.toFixed(1)}%`;
}
async function load(signal?: AbortSignal) {
  const result = await api<Dashboard>("/api/v1/dashboard", {signal});
  if (signal?.aborted) return;
  data.value = result;
  await nextTick();
  draw();
}

function ink() {
  return document.documentElement.classList.contains("dark") ? "#f2f2f2" : "#3b2416";
}

function axis() {
  const color = ink();
  return {
    axisLabel: { color },
    splitLine: { lineStyle: { color: color === "#f2f2f2" ? "#5a5a5a" : "#e0d0bc" } },
  };
}

function byteAxis() {
  const base = axis();
  return {
    ...base,
    minInterval: 1,
    axisLabel: { ...base.axisLabel, formatter: (value: number) => formatBytes(value) },
  };
}

function byteTip() {
  return {
    trigger: "axis" as const,
    valueFormatter: (value: unknown) => formatBytes(Number(value)),
  };
}

function draw() {
  if (!data.value) return;
  const color = ink();
  const series = data.value.traffic_history ?? [];
  if (trafficEl.value) {
    if (!traffic.value) traffic.value = echarts.init(trafficEl.value);
    traffic.value.setOption({
      backgroundColor: "transparent",
      color: ["#8b5a2b", "#c4a574"],
      textStyle: { color, fontFamily: "Comic Neue CN, sans-serif" },
      tooltip: byteTip(),
      legend: { textStyle: { color, fontFamily: "Comic Neue CN, sans-serif" }, top: 0 },
      grid: { left: 72, right: 28, top: 48, bottom: 40 },
      xAxis: { type: "category", data: series.map((point) => formatClock(point.at, true)), ...axis() },
      yAxis: { type: "value", ...byteAxis() },
      series: [
        { name: t("up"), type: "line", smooth: true, areaStyle: { opacity: 0.18 }, data: series.map((point) => point.gaps > 0 ? null : point.up_bytes), showSymbol: series.length < 2 },
        { name: t("down"), type: "line", smooth: true, areaStyle: { opacity: 0.12 }, data: series.map((point) => point.gaps > 0 ? null : point.down_bytes), showSymbol: series.length < 2 },
      ],
    }, { notMerge: true });
  }
  const rows = data.value.devices;
  if (!deviceEl.value) return;
  if (rows.length === 0) {
    deviceChart.value?.clear();
    return;
  }
  if (!deviceChart.value) deviceChart.value = echarts.init(deviceEl.value);
  deviceChart.value.setOption({
    backgroundColor: "transparent",
    color: palette,
    textStyle: { color, fontFamily: "Comic Neue CN, sans-serif" },
    tooltip: byteTip(),
    legend: { textStyle: { color, fontFamily: "Comic Neue CN, sans-serif" }, top: 0, type: "scroll" },
    grid: { left: 72, right: 28, top: 48, bottom: 40 },
    xAxis: { type: "category", data: rows.map((item: StatusDevice) => item.name), ...axis() },
    yAxis: { type: "value", ...byteAxis() },
    series: [
      { name: t("up"), type: "bar", data: rows.map((item) => item.up_bytes), barMaxWidth: 28 },
      { name: t("down"), type: "bar", data: rows.map((item) => item.down_bytes), barMaxWidth: 28 },
    ],
  }, { notMerge: true });
}

function resize() {
  traffic.value?.resize();
  deviceChart.value?.resize();
}

const tip = ref<{ x: number; y: number; time: string; state: string; connections: string } | null>(null);
const tipEl = ref<HTMLElement | null>(null);
const axisMarks = computed(() => {
  const minute = 5 * 60_000;
  const end = Math.ceil(Date.now() / minute) * minute;
  const mark = (time: number) => formatClock(time);
  return [mark(end - slots * minute), mark(end - Math.floor(slots / 2) * minute), mark(end)];
});

function placeTip(event: MouseEvent, width: number, height: number) {
  let x = event.clientX + 12;
  let y = event.clientY + 14;
  if (x + width > window.innerWidth - 8) x = event.clientX - width - 12;
  if (y + height > window.innerHeight - 8) y = event.clientY - height - 12;
  return { x: Math.max(8, x), y: Math.max(8, y) };
}

function showTip(event: MouseEvent, point: StatusBlock) {
 const time = `${formatClock(point.start)} – ${formatClock(point.end)}`;
 const state=point.coverage===0?t("unobserved"):`${point.offline?t("offline"):t("online")} · ${t("coverage",{percent:Number((point.coverage*100).toFixed(1))})}`;
 const connections = point.coverage ? t("historySessions", {count: point.sessions}) : t("unobserved");
 tip.value={...placeTip(event,240,88),time,state,connections};
 nextTick(()=>{const box=tipEl.value?.getBoundingClientRect();if(box&&tip.value) Object.assign(tip.value,placeTip(event,box.width,box.height));});
}

const { loading, stale, wake } = useDashboardStream(load, (item) => { data.value = item; void nextTick(draw); }, () => (data.value?.refresh_sec ?? 5) * 1000);
let themeObserver: MutationObserver | null = null;
watch(() => t("up"), () => { void nextTick(draw); });
onMounted(() => {
  window.addEventListener("resize", resize);
  themeObserver = new MutationObserver(draw);
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
});
onUnmounted(() => {
  themeObserver?.disconnect();
  window.removeEventListener("resize", resize);
  traffic.value?.dispose();
  deviceChart.value?.dispose();
});
</script>

<template>
  <main class="page" v-loading="loading && !data">
    <el-alert v-if="stale" :title="t('stale')" type="warning" show-icon :closable="false" style="margin-bottom: 12px" />
    <el-button v-if="stale" @click="wake">{{ t("refresh") }}</el-button>
    <el-alert v-if="detailDropped" :title="t('detailDropped', { count: data?.connection_persistence?.dropped ?? 0 })" type="error" show-icon :closable="false" style="margin-bottom: 12px" />
    <section class="metrics" v-if="data">
      <article class="m-online">
        <i class="metric-icon" aria-hidden="true"><svg viewBox="0 0 16 16"><path fill="currentColor" d="M6 12q0 1-.25 1.5H5a.5.5 0 0 0 0 1h6a.5.5 0 0 0 0-1h-.75Q10 13 10 12h4c2 0 2-2 2-2V4c0-2-2-2-2-2H2C0 2 0 4 0 4v6c0 2 2 2 2 2z"/></svg></i>
        <div><span>{{ t("onlineDevices") }}</span><strong>{{ compact(data.online_devices) }}</strong></div>
      </article>
      <article class="m-sess">
        <i class="metric-icon" aria-hidden="true"><svg viewBox="0 0 16 16"><path fill="currentColor" d="M11.251.068a.5.5 0 0 1 .227.58L9.677 6.5H13a.5.5 0 0 1 .364.843l-8 8.5a.5.5 0 0 1-.842-.49L6.323 9.5H3a.5.5 0 0 1-.364-.843l8-8.5a.5.5 0 0 1 .615-.09z"/></svg></i>
        <div><span>{{ t("sessions") }}</span><strong>{{ compact(data.active_sessions) }}</strong></div>
      </article>
      <article class="m-fwd">
        <i class="metric-icon" aria-hidden="true"><svg viewBox="0 0 16 16"><path fill="currentColor" d="M7 16h2V6h5a1 1 0 0 0 .8-.4l.975-1.3a.5.5 0 0 0 0-.6L14.8 2.4A1 1 0 0 0 14 2H9v-.586a1 1 0 0 0-2 0V7H2a1 1 0 0 0-.8.4L.225 8.7a.5.5 0 0 0 0 .6l.975 1.3a1 1 0 0 0 .8.4h5z"/></svg></i>
        <div><span>{{ t("forwards") }}</span><strong>{{ compact(data.forwards) }}</strong></div>
      </article>
      <article class="m-port">
        <i class="metric-icon" aria-hidden="true"><svg viewBox="0 0 16 16"><path fill="currentColor" d="M2 2a2 2 0 0 0-2 2v1a2 2 0 0 0 2 2h5.5v3A1.5 1.5 0 0 0 6 11.5H.5a.5.5 0 0 0 0 1H6A1.5 1.5 0 0 0 7.5 14h1a1.5 1.5 0 0 0 1.5-1.5h5.5a.5.5 0 0 0 0-1H10A1.5 1.5 0 0 0 8.5 10V7H14a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2zm.5 3a.5.5 0 1 1 0-1 .5.5 0 0 1 0 1m2 0a.5.5 0 1 1 0-1 .5.5 0 0 1 0 1"/></svg></i>
        <div><span>{{ t("dataPorts") }}</span><strong>{{ compact(data.data_ports) }}</strong></div>
      </article>
      <article class="m-port">
        <i class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="4" width="8" height="7" rx="1"/><rect x="14" y="4" width="8" height="7" rx="1"/><path d="M6 11v6h12v-6M12 17v4"/></svg></i>
        <div><span>Weroxy / Legacy</span><strong>{{ compact(data.online_weroxy_devices) }} / {{ compact(data.online_legacy_devices) }}</strong></div>
      </article>
      <article class="m-up">
        <i class="metric-icon" aria-hidden="true"><svg viewBox="0 0 16 16"><path fill="currentColor" d="M16 8A8 8 0 1 0 0 8a8 8 0 0 0 16 0m-7.5 3.5a.5.5 0 0 1-1 0V5.707L5.354 7.854a.5.5 0 1 1-.708-.708l3-3a.5.5 0 0 1 .708 0l3 3a.5.5 0 0 1-.708.708L8.5 5.707z"/></svg></i>
        <div><span>{{ t("up") }}</span><strong>{{ formatBytes(data.up_bytes) }}</strong></div>
      </article>
      <article class="m-down">
        <i class="metric-icon" aria-hidden="true"><svg viewBox="0 0 16 16"><path fill="currentColor" d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0M8.5 4.5a.5.5 0 0 0-1 0v5.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293z"/></svg></i>
        <div><span>{{ t("down") }}</span><strong>{{ formatBytes(data.down_bytes) }}</strong></div>
      </article>
      <article class="m-rej">
        <i class="metric-icon" aria-hidden="true"><svg viewBox="0 0 16 16"><path fill="currentColor" d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0M5.354 4.646a.5.5 0 1 0-.708.708L7.293 8l-2.647 2.646a.5.5 0 0 0 .708.708L8 8.707l2.646 2.647a.5.5 0 0 0 .708-.708L8.707 8l2.647-2.646a.5.5 0 0 0-.708-.708L8 7.293z"/></svg></i>
        <div><span>{{ t("rejected") }}</span><strong>{{ compact(data.rejected) }}</strong></div>
      </article>
    </section>
    <details v-if="data && failureTotal" class="fault-metrics" aria-live="polite">
      <summary>{{ t("connectionFailures") }} · {{ compact(failureTotal) }}</summary>
      <p class="reason">{{ t("failuresSinceStart") }}</p>
      <span>{{ t("dataDialFailures") }}: {{ compact(data.failures?.data_dial_failures ?? 0) }}</span>
      <span>{{ t("targetDialFailures") }}: {{ compact(data.failures?.target_dial_failures ?? 0) }}</span>
      <span>{{ t("targetDenials") }}: {{ compact(data.failures?.target_denials ?? 0) }}</span>
      <span>{{ t("clientBusyFailures") }}: {{ compact(data.failures?.client_busy ?? 0) }}</span>
    </details>
    <section class="status-panel">
      <header>
        <strong>{{ t("statusBoard") }}</strong>
        <span><i class="swatch green"></i>0–3</span><span><i class="swatch yellow"></i>4–10</span><span><i class="swatch orange"></i>&gt;10</span>

        <span><i class="swatch offline"></i>{{ t("offline") }}</span>
      </header>
      <p v-if="data && board.length === 0" class="status-empty">{{ t("noDevices") }}</p>
      <article v-for="item in board" :key="item.protocol + item.name" class="status-item">
        <div class="status-id">
          <i class="dot" :class="statusTone(item.online, item.sessions, item.online_known)"></i>
          <div>
            <router-link :title="item.name" :to="'/devices/' + item.name">{{ item.name }}</router-link>
            <el-tag size="small" :class="item.protocol === 'weroxy' ? 'tag-weroxy' : 'tag-legacy'">{{ item.protocol === "weroxy" ? "Weroxy" : "Legacy" }}</el-tag>
          </div>
        </div>
        <div class="status-now">
          <span><b class="n-sess">{{ item.sessions }}</b> {{ t("sessions") }}</span>
          <span class="n-up">↑ {{ formatBytes(item.up_bytes) }}</span>
          <span>{{ t("controlRTT") }}: {{ item.control_rtt_ms ?? "—" }}<small v-if="item.control_rtt_ms != null">ms</small></span>
          <span class="n-down">↓ {{ formatBytes(item.down_bytes) }}</span>
        </div>
        <div class="status-bar">
          <span v-if="uptime(item.history)" class="status-uptime">{{ uptime(item.history) }} {{ t("uptime") }}</span>
          <div class="ticks" :style="{ gridTemplateColumns: `repeat(${slots}, minmax(0, 1fr))` }" @mouseleave="tip = null">
          <i
            v-for="(point, index) in blocks(item.history)"
            :key="index"
            class="tick"
            :class="[point.coverage ? statusTone(!point.offline, point.sessions) : 'none', {partial: point.coverage > 0 && point.coverage < 1}]"
            @mouseenter="showTip($event, point)"
          ></i>
          </div>
        </div>
      </article>
      <div v-if="board.length" class="status-axis">
        <span></span>
        <span></span>
        <div>
          <span v-for="(mark, index) in axisMarks" :key="index">{{ mark }}</span>
        </div>
      </div>
      <div v-if="tip" ref="tipEl" class="status-tip" :style="{ left: tip.x + 'px', top: tip.y + 'px' }">
        <strong>{{ tip.time || t("unobserved") }}</strong>
        <span class="status-tip-count">{{ tip.connections }}</span>
        <span>{{ tip.state }}</span>
      </div>
    </section>
    <div class="charts">
      <div>
        <h3>{{ t("totalTraffic") }}</h3>
        <div ref="trafficEl" class="chart"></div>
      </div>
      <div>
        <h3>{{ t("trafficTotal") }}</h3>
        <div ref="deviceEl" class="chart"></div>
      </div>
    </div>
  </main>
</template>
