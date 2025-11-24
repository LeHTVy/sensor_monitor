<template>
  <v-app>
    <router-view />
  </v-app>
</template>

<script setup lang="ts">
import { RouterView } from 'vue-router'
import { onMounted } from 'vue'
import { useTheme } from 'vuetify'
import { useThemeStore } from '@/stores/theme'

const vuetifyTheme = useTheme()
const themeStore = useThemeStore()

onMounted(() => {
  themeStore.setVuetifyTheme(vuetifyTheme)
  themeStore.initTheme()
})
</script>
