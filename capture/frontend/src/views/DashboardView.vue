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

    <v-main class="dashboard-main">
      <v-container fluid class="pa-4">
        <!-- Stats Cards -->
        <StatsCards />

        <!-- Filter Tabs -->
        <v-card class="mb-6 filter-tabs-card" elevation="2">
          <v-tabs
            v-model="dashboardStore.currentFilter"
            @update:model-value="(value: 'all' | 'attack' | 'honeypot' | 'traffic') => dashboardStore.setFilter(value)"
            color="primary"
            align-tabs="center"
            bg-color="transparent"
          >
            <v-tab value="all" class="text-capitalize">
              <v-icon start>mdi-format-list-bulleted</v-icon>
              All Logs
            </v-tab>
            <v-tab value="attack" class="text-capitalize">
              <v-icon start>mdi-shield-alert</v-icon>
              Attacks
            </v-tab>
            <v-tab value="honeypot" class="text-capitalize">
              <v-icon start>mdi-bee</v-icon>
              Honeypot
            </v-tab>
            <v-tab value="traffic" class="text-capitalize">
              <v-icon start>mdi-traffic-light</v-icon>
              Traffic
            </v-tab>
          </v-tabs>
          
          <!-- Date Filter -->
          <v-card-text class="d-flex align-center flex-wrap ga-2">
            <v-icon>mdi-calendar-filter</v-icon>
            <span class="text-subtitle-2 mr-2">Filter by Date:</span>
            <v-text-field
              v-model="dashboardStore.dateFrom"
              type="date"
              label="From"
              density="compact"
              variant="outlined"
              hide-details
              style="max-width: 180px"
              @update:model-value="dashboardStore.loadLogs()"
            />
            <v-text-field
              v-model="dashboardStore.dateTo"
              type="date"
              label="To"
              density="compact"
              variant="outlined"
              hide-details
              style="max-width: 180px"
              @update:model-value="dashboardStore.loadLogs()"
            />
            <v-btn
              v-if="dashboardStore.dateFrom || dashboardStore.dateTo"
              @click="dashboardStore.clearDateFilter()"
              color="error"
              size="small"
              variant="text"
            >
              <v-icon start>mdi-close</v-icon>
              Clear
            </v-btn>
          </v-card-text>
        </v-card>

        <!-- Logs Table -->
        <LogsTable
          :logs="dashboardStore.logs"
          :loading="dashboardStore.loading || refreshStore.isRefreshing"
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
  border-radius: 16px;
  backdrop-filter: blur(10px);
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
}

.dashboard-main {
  background: linear-gradient(135deg, rgba(var(--v-theme-background), 0.95) 0%, rgba(var(--v-theme-surface), 0.9) 100%);
  min-height: 100vh;
}

.filter-tabs-card {
  border-radius: 12px;
  overflow: hidden;
}

:deep(.v-tabs) {
  background-color: transparent;
}

:deep(.v-tab) {
  min-width: 120px;
  font-weight: 500;
}
</style>
