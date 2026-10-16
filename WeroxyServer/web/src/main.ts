import { createApp } from "vue";
import ElementPlus from "element-plus";
import "element-plus/dist/index.css";
import "element-plus/theme-chalk/dark/css-vars.css";
import App from "./App.vue";
import { i18n } from "./i18n";
import { router } from "./router";
import "./styles.css";

createApp(App).use(router).use(i18n).use(ElementPlus).mount("#app");
