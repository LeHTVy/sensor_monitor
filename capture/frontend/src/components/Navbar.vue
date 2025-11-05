<template>
  <v-app-bar color="primary" dark class="floating-app-bar" :elevation="8">
    <v-app-bar-title>
      <v-icon icon="mdi-shield-account" class="mr-2" />
      Capture Server Dashboard
    </v-app-bar-title>

    <v-spacer />

    <!-- Navigation Buttons -->
    <v-btn
      :to="{ name: 'dashboard' }"
      :color="isActiveRoute('dashboard') ? 'secondary' : 'default'"
      class="mr-2"
      variant="text"
    >
      <v-icon left>mdi-view-dashboard</v-icon>
      Dashboard
    </v-btn>

    <v-btn
      :to="{ name: 'all-logs' }"
      :color="isActiveRoute('all-logs') ? 'secondary' : 'default'"
      class="mr-2"
      variant="text"
    >
      <v-icon left>mdi-format-list-bulleted</v-icon>
      All Logs
    </v-btn>

    <v-spacer />

    <!-- Theme Toggle -->
    <v-btn @click="toggleTheme" color="secondary" class="mr-2">
      <v-icon left>{{ isDark ? 'mdi-weather-sunny' : 'mdi-weather-night' }}</v-icon>
      {{ isDark ? 'Light' : 'Dark' }}
    </v-btn>

    <!-- Logout -->
    <v-btn @click="authStore.logout" color="error">
      <v-icon left>mdi-logout</v-icon>
      Logout
    </v-btn>
  </v-app-bar>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useTheme } from 'vuetify'
import { useAuthStore } from '@/stores/auth'

const authStore = useAuthStore()
const route = useRoute()
const router = useRouter()
const theme = useTheme()

const isDark = computed(() => theme.global.current.value.dark)

function toggleTheme() {
  theme.global.name.value = isDark.value ? 'light' : 'dark'
}

function isActiveRoute(routeName: string): boolean {
  return route.name === routeName
}
</script>

<style scoped>
.floating-app-bar {
  position: sticky;
  top: 12px;
  margin: 12px;
  border-radius: 16px;
  backdrop-filter: blur(10px);
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
}
</style>

