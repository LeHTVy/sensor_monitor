<template>
  <v-app>
    <v-app-bar color="primary" dark class="floating-app-bar" :elevation="8">
      <v-app-bar-title>
        <v-icon icon="mdi-shield-account" class="mr-2" />
        Capture Server Dashboard
      </v-app-bar-title>

      <v-spacer />

      <v-btn @click="toggleTheme" color="secondary" class="mr-2">
        <v-icon left>{{ isDark ? 'mdi-weather-sunny' : 'mdi-weather-night' }}</v-icon>
        {{ isDark ? 'Light' : 'Dark' }}
      </v-btn>

      <v-btn @click="authStore.logout" color="error">
        <v-icon left>mdi-logout</v-icon>
        Logout
      </v-btn>
    </v-app-bar>

    <v-main>
      <v-container fluid class="pt-12">
        <!-- Stats Cards -->
        <StatsCards />

        <!-- Filter Tabs -->
        <v-card class="mb-6">
          <v-tabs
            v-model="dashboardStore.currentFilter"
                     @update:model-value="(value: 'all' | 'attack' | 'honeypot' | 'traffic') => dashboardStore.setFilter(value)"
            color="primary"
            align-tabs="center"
          >
            <v-tab value="all">All Logs</v-tab>
            <v-tab value="attack">Attacks</v-tab>
            <v-tab value="honeypot">Honeypot</v-tab>
            <v-tab value="traffic">Traffic</v-tab>
          </v-tabs>
        </v-card>

        <!-- Logs Table -->
        <LogsTable
          :logs="dashboardStore.logs"
          :loading="dashboardStore.loading || refreshStore.isRefreshing"
          @refresh="refreshStore.refreshData"
        />

        <!-- Attack Patterns -->
        <PatternsTable :patterns="dashboardStore.patterns" />
      </v-container>
    </v-main>
  </v-app>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, computed } from 'vue'
import { useTheme } from 'vuetify'
import { useAuthStore } from '@/stores/auth'
import { useDashboardStore } from '@/stores/dashboard'
import { useRefreshStore } from '@/stores/refreshData'
import StatsCards from '@/components/StatsCards.vue'
import LogsTable from '@/components/LogsTable.vue'
import PatternsTable from '@/components/PatternsTable.vue'

const authStore = useAuthStore()
const dashboardStore = useDashboardStore()
const refreshStore = useRefreshStore()
const theme = useTheme()

const isDark = computed(() => theme.global.current.value.dark)

function toggleTheme() {
  theme.global.name.value = isDark.value ? 'light' : 'dark'
}

onMounted(() => {
  if (authStore.isLoggedIn) {
    refreshStore.refreshData()
    refreshStore.startAutoRefresh(1000)
  }
})

onUnmounted(() => {
  refreshStore.stopAutoRefresh()
})
</script>

<style scoped>
.floating-app-bar {
  position: sticky;
  top: 12px;
  margin: 12px;
  border-radius: 12px;
  backdrop-filter: blur(6px);
}
</style>
