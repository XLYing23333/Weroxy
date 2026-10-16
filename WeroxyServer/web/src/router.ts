import { ref } from "vue";
import { createRouter, createWebHistory } from "vue-router";
import { api } from "./api";
const Dashboard = () => import("./views/Dashboard.vue");
const Devices = () => import("./views/Devices.vue");
const Login = () => import("./views/Login.vue");
const Settings = () => import("./views/Settings.vue");
const Setup = () => import("./views/Setup.vue");

export const failedPage = ref<string | null>(null);

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/login", component: Login },
    { path: "/setup", component: Setup },
    { path: "/init:token([a-f0-9]{64})", component: Setup },
    { path: "/", component: Dashboard },
    { path: "/devices", component: Devices },
    { path: "/devices/:name", component: Devices },
    { path: "/settings", component: Settings },
  ],
});

router.beforeEach(async (to) => {
  const token=typeof to.params.token==="string"?to.params.token:"";
  const state=await api<{initialized:boolean;authorized:boolean}>("/api/v1/setup",{headers:token?{"X-Weroxy-Setup":token}:{}});
  if(!state.initialized) return to.path==="/setup"||(token&&state.authorized)?true:"/setup";
  if(to.path==="/setup"||token) return "/login";
  if (to.path === "/login") return true;
  try {
    await api("/api/v1/auth/session");
    return true;
  } catch {
    return "/login";
  }
});

router.onError((_error, to) => { failedPage.value = to.fullPath; });
router.afterEach((_to, _from, failure) => { if (!failure) failedPage.value = null; });
