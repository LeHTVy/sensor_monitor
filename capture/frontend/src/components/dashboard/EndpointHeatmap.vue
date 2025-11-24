<template>
  <v-card elevation="2" rounded="lg" class="endpoint-heatmap-card">
    <v-card-title class="d-flex align-center">
      <v-icon icon="mdi-fire" color="error" class="mr-2" />
      <span class="text-h6 font-weight-bold">Attack Heatmap</span>
      <v-spacer />
      <v-chip size="small" variant="outlined">
        Top {{ heatmapData.length }} Endpoints
      </v-chip>
    </v-card-title>

    <v-card-text>
      <div v-if="loading" class="text-center py-8">
        <v-progress-circular indeterminate color="primary" />
      </div>

      <div v-else-if="error" class="text-center py-8">
        <v-icon icon="mdi-alert-circle" color="error" size="48" />
        <p class="text-body-2 text-error mt-2">{{ error }}</p>
      </div>

      <div v-else-if="!hasData" class="text-center py-8">
        <v-icon icon="mdi-target" size="64" color="grey-lighten-1" />
        <p class="text-body-2 text-medium-emphasis mt-4">No endpoint data</p>
      </div>

      <v-list v-else density="compact" class="py-0">
        <v-list-item
          v-for="(item, index) in heatmapData"
          :key="item.endpoint"
          class="heatmap-item mb-2"
          rounded="lg"
          :style="{ borderLeft: `4px solid ${getThreatColor(item.threat_levels)}` }"
        >
          <template #prepend>
            <v-avatar :color="getThreatColor(item.threat_levels)" size="48" class="mr-3">
              <span class="text-h6 font-weight-bold">{{ index + 1 }}</span>
            </v-avatar>
          </template>

          <v-list-item-title class="font-weight-bold mb-1">
            <v-icon icon="mdi-link-variant" size="small" class="mr-1" />
            {{ item.endpoint }}
          </v-list-item-title>

          <v-list-item-subtitle class="d-flex align-center flex-wrap ga-2">
            <v-chip size="x-small" color="error" variant="tonal">
              {{ item.count }} attacks
            </v-chip>
            <v-chip size="x-small" color="primary" variant="tonal">
              {{ item.unique_ips }} IPs
            </v-chip>
            <v-chip
              v-for="(count, method) in item.methods"
              :key="method"
              size="x-small"
              variant="outlined"
            >
              {{ method }}
            </v-chip>
          </v-list-item-subtitle>

          <template #append>
            <div class="heatmap-bar-container">
              <v-progress-linear
                :model-value="(item.count / maxCount) * 100"
                :color="getThreatColor(item.threat_levels)"
                height="8"
                rounded
                class="heatmap-bar"
              />
              <span class="text-caption text-medium-emphasis ml-2">
                {{ ((item.count / maxCount) * 100).toFixed(0) }}%
              </span>
            </div>
          </template>
        </v-list-item>
      </v-list>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'

const API_KEY = 'capture_secure_key_2024'
const API_BASE = '/api'

interface HeatmapItem {
  endpoint: string
  count: number
  unique_ips: number
  methods: Record<string, number>
  threat_levels: Record<string, number>
}

const heatmapData = ref<HeatmapItem[]>([])
const loading = ref(false)
const error = ref('')
let refreshInterval: number | null = null

const hasData = computed(() => heatmapData.value.length > 0)

const maxCount = computed(() =>
  Math.max(...heatmapData.value.map(d => d.count), 1)
)

const getThreatColor = (threats: Record<string, number>): string => {
  if (!threats) return '#10B981'
  if (threats.critical > 0) return '#EF4444'
  if (threats.high > 0) return '#F59E0B'
  if (threats.medium > 0) return '#FCD34D'
  return '#10B981'
}

const fetchHeatmap = async () => {
  try {
    loading.value = true
    error.value = ''
    
    const response = await fetch(
      `${API_BASE}/logs/heatmap?hours=24&limit=10`,
      { headers: { 'X-API-Key': API_KEY } }
    )
    
    if (!response.ok) throw new Error('Failed to fetch heatmap data')
    
    const data = await response.json()
    heatmapData.value = data.heatmap || []
  } catch (err: any) {
    error.value = err.message || 'Error loading heatmap'
    console.error('Heatmap fetch error:', err)
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  fetchHeatmap()
  refreshInterval = window.setInterval(fetchHeatmap, 60000) // Refresh every 60s
})

onUnmounted(() => {
  if (refreshInterval) clearInterval(refreshInterval)
})
</script>

<style scoped>
.endpoint-heatmap-card {
  height: 100%;
}

.heatmap-item {
  transition: all 0.2s ease;
  background: rgba(0, 0, 0, 0.02);
}

.heatmap-item:hover {
  background: rgba(0, 0, 0, 0.05);
  transform: translateX(4px);
}

.heatmap-bar-container {
  display: flex;
  align-items: center;
  min-width: 150px;
}

.heatmap-bar {
  min-width: 120px;
}
</style>
