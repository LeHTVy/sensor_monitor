<template>
  <v-app>
    <Navbar />

    <v-main class="dashboard-main">
      <v-container fluid class="pa-6">
        <!-- Hero Stats -->
        <v-row class="mb-4">
          <v-col cols="12">
            <HeroSection />
          </v-col>
        </v-row>

        <!-- Main Content Area -->
        <v-row>
          <!-- World Map -->
          <v-col cols="12">
            <WorldMap />
          </v-col>
        </v-row>

        <!-- Charts Row -->
        <v-row class="mt-4">
          <v-col cols="12" md="8">
            <AttackTimeline />
          </v-col>
          <v-col cols="12" md="4">
            <EndpointHeatmap />
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
import HeroSection from '@/components/dashboard/HeroSection.vue'
import AttackTimeline from '@/components/dashboard/AttackTimeline.vue'
import EndpointHeatmap from '@/components/dashboard/EndpointHeatmap.vue'
import WorldMap from '@/components/dashboard/WorldMap.vue'

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
.dashboard-main {
  background: var(--bg-primary);
  min-height: 100vh;
}
</style>
