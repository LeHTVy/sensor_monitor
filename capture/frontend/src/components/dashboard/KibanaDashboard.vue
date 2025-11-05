<template>
  <v-card class="kibana-dashboard" elevation="2" rounded="lg">
    <v-card-title class="d-flex align-center">
      <v-icon icon="mdi-chart-line" class="mr-2" />
      Traffic Frequency Analytics
      <v-spacer />
      <v-chip size="small" color="info" variant="outlined">
        <v-icon start size="16">mdi-update</v-icon>
        Real-time
      </v-chip>
    </v-card-title>

    <v-card-text>
      <!-- Iframe for Kibana Dashboard -->
      <div v-if="kibanaUrl" class="kibana-iframe-container">
        <iframe
          :src="kibanaUrl"
          class="kibana-iframe"
          frameborder="0"
          allow="fullscreen"
          @load="onIframeLoad"
        />
      </div>

      <!-- Fallback: Show Elasticsearch stats if Kibana not available -->
      <div v-else class="kibana-fallback">
        <v-alert type="info" variant="tonal" class="mb-4">
          <v-alert-title>Kibana Dashboard</v-alert-title>
          Connecting to Kibana dashboard...
        </v-alert>

        <!-- Basic Traffic Stats -->
        <v-row>
          <v-col cols="12" md="6">
            <v-card variant="outlined" class="mb-4">
              <v-card-title class="text-subtitle-1">Traffic Overview (Last 24h)</v-card-title>
              <v-card-text>
                <div class="text-h4 font-weight-bold mb-2">{{ trafficStats.last24h }}</div>
                <div class="text-caption text-medium-emphasis">Requests</div>
              </v-card-text>
            </v-card>
          </v-col>

          <v-col cols="12" md="6">
            <v-card variant="outlined" class="mb-4">
              <v-card-title class="text-subtitle-1">Peak Hour</v-card-title>
              <v-card-text>
                <div class="text-h4 font-weight-bold mb-2">{{ trafficStats.peakHour }}</div>
                <div class="text-caption text-medium-emphasis">Most active time</div>
              </v-card-text>
            </v-card>
          </v-col>
        </v-row>

        <!-- Traffic Chart Placeholder -->
        <v-card variant="outlined">
          <v-card-title class="text-subtitle-1">Traffic Frequency Chart</v-card-title>
          <v-card-text>
            <div class="chart-placeholder">
              <v-icon icon="mdi-chart-line" size="64" class="mb-4" />
              <p class="text-body-2 text-medium-emphasis">
                Traffic frequency visualization will be displayed here
              </p>
            </div>
          </v-card-text>
        </v-card>
      </div>

      <!-- Loading State -->
      <v-overlay v-if="loading" contained class="align-center justify-center">
        <v-progress-circular indeterminate color="primary" size="64" />
      </v-overlay>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useDashboardStore, type Log } from '@/stores/dashboard'
import type { ExtendedLog } from '@/types/logs'
import { getLogTimestamp } from '@/types/logs'

const dashboardStore = useDashboardStore()
const loading = ref(true)

// Kibana URL - should be configured from environment or API
const kibanaUrl = computed(() => {
  // Get Kibana URL from environment or API
  const baseUrl = import.meta.env.VITE_KIBANA_URL || 'http://10.8.0.1:5601'
  // Embed Kibana dashboard - you'll need to create a dashboard in Kibana and get its ID
  const dashboardId = import.meta.env.VITE_KIBANA_DASHBOARD_ID || 'sensor-traffic-dashboard'

  if (!dashboardId) {
    return null
  }

  // Return Kibana embed URL
  return `${baseUrl}/app/kibana#/dashboard/${dashboardId}?embed=true&_g=(refreshInterval:(pause:!f,value:5000))`
})

const trafficStats = computed(() => {
  // Calculate from dashboard store or fetch from API
  const logs = dashboardStore.logs || []
  const now = new Date()
  const last24h = new Date(now.getTime() - 24 * 60 * 60 * 1000)

  const last24hLogs = logs.filter((log: ExtendedLog) => {
    const logTime = getLogTimestamp(log)
    return logTime >= last24h
  })

  // Calculate peak hour
  const hourCounts: { [key: number]: number } = {}
  last24hLogs.forEach((log: ExtendedLog) => {
    const logTime = getLogTimestamp(log)
    const hour = logTime.getHours()
    hourCounts[hour] = (hourCounts[hour] || 0) + 1
  })

  const peakHour = Object.entries(hourCounts).reduce((a, b) =>
    hourCounts[parseInt(a[0])] > hourCounts[parseInt(b[0])] ? a : b
  )[0]

  return {
    last24h: last24hLogs.length,
    peakHour: `${peakHour}:00`
  }
})

function onIframeLoad() {
  loading.value = false
}

onMounted(() => {
  // If no Kibana URL, simulate loading completion
  if (!kibanaUrl.value) {
    setTimeout(() => {
      loading.value = false
    }, 1000)
  }
})
</script>

<style scoped>
.kibana-dashboard {
  margin-top: 24px;
}

.kibana-iframe-container {
  position: relative;
  width: 100%;
  height: 600px;
  border-radius: 8px;
  overflow: hidden;
  background: #f5f5f5;
}

.kibana-iframe {
  width: 100%;
  height: 100%;
  border: none;
}

.kibana-fallback {
  padding: 24px;
}

.chart-placeholder {
  text-align: center;
  padding: 48px;
  color: rgba(var(--v-theme-on-surface), 0.38);
}

:deep(.v-overlay) {
  background-color: rgba(255, 255, 255, 0.8);
}
</style>

