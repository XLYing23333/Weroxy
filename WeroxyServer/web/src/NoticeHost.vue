<script setup lang="ts">
import { useI18n } from "vue-i18n";
import { dismiss, notices } from "./notice";

const { t } = useI18n();
</script>

<template>
  <TransitionGroup name="notice" tag="div" class="notices">
    <article v-for="item in notices" :key="item.id" class="notice" :class="item.tone">
      <i class="notice-bar" :style="{ animationDuration: item.duration + 'ms' }" />
      <div class="notice-body">
        <strong>{{ item.title }}</strong>
        <p v-if="item.message">{{ item.message }}</p>
      </div>
      <button type="button" class="notice-x" :aria-label="t('cancel')" @click="dismiss(item.id)">×</button>
    </article>
  </TransitionGroup>
</template>
