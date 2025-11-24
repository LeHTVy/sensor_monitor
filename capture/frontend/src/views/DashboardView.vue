<template>
  <v-app>
    <Navbar />

    <v-main>
      <v-container fluid class="pa-4">
        <!-- Hero Section -->
        <HeroSection />

        <!-- Stats Cards -->
        <StatsCards />

        <!-- Charts Section -->
        <v-row class="mt-4">
          <v-col cols="12" lg="8">
            <AttackTimeline />
          </v-col>
          <v-col cols="12" lg="4">
            <EndpointHeatmap />
          </v-col>
        </v-row>

        <!-- Kibana Dashboard -->
        <div class="mt-4">
          <KibanaDashboard />
        </div>
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
import HeroSection from '@/components/dashboard/HeroSection.vue'
import KibanaDashboard from '@/components/dashboard/KibanaDashboard.vue'
import StatsCards from '@/components/StatsCards.vue'
import AttackTimeline from '@/components/dashboard/AttackTimeline.vue'
import EndpointHeatmap from '@/components/dashboard/EndpointHeatmap.vue'

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
/* Dashboard main container styling */
:deep(.v-main) {
  background: linear-gradient(135deg, rgba(var(--v-theme-background), 0.95) 0%, rgba(var(--v-theme-surface), 0.9) 100%);
  min-height: 100vh;
}
</style>
