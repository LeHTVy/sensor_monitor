<template>
  <v-app>
    <Navbar />

    <v-main>
      <v-container fluid class="pa-4">
        <v-row>
          <!-- Filter Panel (Sidebar) -->
          <v-col cols="12" md="3">
            <FilterPanel />
          </v-col>

          <!-- Main Content -->
          <v-col cols="12" md="9">
            <!-- Logs Table -->
            <LogsTable
              :logs="dashboardStore.logs"
              :loading="dashboardStore.loading || refreshStore.isRefreshing"
              class="mb-6"
            />

            <!-- Attack Patterns -->
            <PatternsTable :patterns="dashboardStore.patterns" />
          </v-col>
        </v-row>
      </v-container>
    </v-main>
  </v-app>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { useDashboardStore } from '@/stores/dashboard'
import { useRefreshStore } from '@/stores/refreshData'
import Navbar from '@/components/Navbar.vue'
import FilterPanel from '@/components/alllogs/FilterPanel.vue'
import LogsTable from '@/components/alllogs/LogsTable.vue'
import PatternsTable from '@/components/alllogs/PatternsTable.vue'

const authStore = useAuthStore()
const dashboardStore = useDashboardStore()
const refreshStore = useRefreshStore()

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
:deep(.v-main) {
  background: linear-gradient(135deg, rgba(var(--v-theme-background), 0.95) 0%, rgba(var(--v-theme-surface), 0.9) 100%);
  min-height: 100vh;
}
</style>

