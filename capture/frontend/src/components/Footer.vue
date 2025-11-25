<template>
  <v-footer app class="footer-container d-flex flex-column py-4">
    <div class="d-flex align-center w-100 px-4">
      <div class="d-flex align-center">
        <v-img :src="logoSrc" class="mr-2" width="24" height="24" contain />
        <span class="text-subtitle-1 font-weight-bold text-primary">SHADOWTRAP</span>
        <v-divider vertical class="mx-3" />
        <span class="text-caption text-medium-emphasis font-italic">Hunt in Silence, Strike in Darkness</span>
      </div>

      <v-spacer />

      <div class="text-caption text-medium-emphasis">
        Made by <span class="font-weight-bold text-primary">VLH</span>
      </div>
    </div>
  </v-footer>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useThemeStore } from '@/stores/theme'

const themeStore = useThemeStore()

const logoSrc = computed(() => {
  return themeStore.isDark ? '/Logo-Golden.png' : '/Logo-Blue.png'
})
</script>

<style scoped>
.footer-container {
  background: rgb(var(--v-theme-surface));
  border-top: 1px solid rgba(var(--v-theme-primary), 0.1);
  z-index: 100;
}
</style>
