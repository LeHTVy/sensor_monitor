<template>
  <v-card class="hero-section" elevation="0" color="transparent">
    <v-card-text class="hero-content">
      <div class="hero-title">
        <v-icon icon="mdi-shield-check" size="64" class="mb-4 hero-icon" />
        <h1 class="text-h3 font-weight-bold mb-4">Capture Server Dashboard</h1>
        <p class="text-h6 text-medium-emphasis mb-6">
          Real-time security monitoring and threat analysis platform
        </p>
      </div>

      <v-row class="hero-stats">
        <v-col cols="12" sm="6" md="3">
          <v-card class="stat-card" elevation="2" rounded="lg">
            <v-card-text class="text-center">
              <v-icon icon="mdi-radar" size="32" color="error" class="mb-2" />
              <div class="text-h5 font-weight-bold">{{ stats.toolScans }}</div>
              <div class="text-caption text-medium-emphasis">Security Tool Scans</div>
            </v-card-text>
          </v-card>
        </v-col>

        <v-col cols="12" sm="6" md="3">
          <v-card class="stat-card" elevation="2" rounded="lg">
            <v-card-text class="text-center">
              <v-icon icon="mdi-console" size="32" color="warning" class="mb-2" />
              <div class="text-h5 font-weight-bold">{{ stats.interactiveAttacks }}</div>
              <div class="text-caption text-medium-emphasis">Interactive Attacks</div>
            </v-card-text>
          </v-card>
        </v-col>

        <v-col cols="12" sm="6" md="3">
          <v-card class="stat-card" elevation="2" rounded="lg">
            <v-card-text class="text-center">
              <v-icon icon="mdi-help-circle" size="32" color="info" class="mb-2" />
              <div class="text-h5 font-weight-bold">{{ stats.normalBrowsing }}</div>
              <div class="text-caption text-medium-emphasis">Unknown Tools</div>
            </v-card-text>
          </v-card>
        </v-col>

        <v-col cols="12" sm="6" md="3">
          <v-card class="stat-card" elevation="2" rounded="lg">
            <v-card-text class="text-center">
              <v-icon icon="mdi-database" size="32" color="success" class="mb-2" />
              <div class="text-h5 font-weight-bold">{{ stats.totalLogs }}</div>
              <div class="text-caption text-medium-emphasis">Total Logs</div>
            </v-card-text>
          </v-card>
        </v-col>
      </v-row>

      <div class="hero-description mt-8">
        <p class="text-body-1 text-medium-emphasis">
          Monitor and analyze security events in real-time. Track security tool scans (nmap, masscan, nikto, etc.),
          interactive attacks (POST requests, shells, browser-based attacks), and logs with unknown detection tools.
        </p>
      </div>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useDashboardStore } from '@/stores/dashboard'

const dashboardStore = useDashboardStore()

const stats = computed(() => ({
  toolScans: dashboardStore.stats.tool_scan_logs || 0,
  interactiveAttacks: dashboardStore.stats.interactive_attack_logs || 0,
  normalBrowsing: dashboardStore.stats.normal_browsing_logs || 0,
  totalLogs: dashboardStore.stats.total_logs_received || 0
}))
</script>

<style scoped>
.hero-section {
  margin-bottom: 32px;
}

.hero-content {
  padding: 48px 24px;
}

.hero-title {
  text-align: center;
  margin-bottom: 32px;
}

.hero-icon {
  animation: pulse 2s ease-in-out infinite;
}

@keyframes pulse {
  0%, 100% {
    opacity: 1;
    transform: scale(1);
  }
  50% {
    opacity: 0.8;
    transform: scale(1.05);
  }
}

.hero-stats {
  margin-top: 32px;
}

.stat-card {
  transition: transform 0.2s ease, box-shadow 0.2s ease;
  height: 100%;
}

.stat-card:hover {
  transform: translateY(-4px);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.15) !important;
}

.hero-description {
  text-align: center;
  max-width: 800px;
  margin: 0 auto;
}
</style>

