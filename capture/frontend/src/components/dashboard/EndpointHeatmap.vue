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
import { ref, computed, watch, onMounted } from 'vue'
import { useDashboardStore } from '@/stores/dashboard'

const dashboardStore = useDashboardStore()

interface HeatmapItem {
  endpoint: string
  count: number
  unique_ips: number
  methods: Record<string, number>
  threat_levels: Record<string, number>
}

const heatmapData = ref<HeatmapItem[]>([])

const loading = computed(() => dashboardStore.loading)
const error = ref('') // Store doesn't expose error, but we can assume no error if logs are loaded
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

const generateHeatmapData = () => {
  const logs = dashboardStore.logs
  
  if (logs.length === 0) {
    heatmapData.value = []
    return
  }
  
  // Aggregate by endpoint
  const endpointMap = new Map<string, HeatmapItem>()
  const ipSets = new Map<string, Set<string>>()
  
  logs.forEach((log: any) => {
    const endpoint = log.path || log.url || log.request_path || '/'
    const ip = log.src_ip || log.ip || 'unknown'
    const method = log.method || 'GET'
    const threat = log.threat_level || 'low'
    
    if (!endpointMap.has(endpoint)) {
      endpointMap.set(endpoint, {
        endpoint,
        count: 0,
        unique_ips: 0,
        methods: {},
        threat_levels: {}
      })
      ipSets.set(endpoint, new Set())
    }
    
    const item = endpointMap.get(endpoint)!
    const ips = ipSets.get(endpoint)!
    
    item.count++
    ips.add(ip)
    item.unique_ips = ips.size
    item.methods[method] = (item.methods[method] || 0) + 1
    item.threat_levels[threat] = (item.threat_levels[threat] || 0) + 1
  })
  
  heatmapData.value = Array.from(endpointMap.values())
    .sort((a, b) => b.count - a.count)
    .slice(0, 10)
}

onMounted(() => {
  generateHeatmapData()
})

// Watch for changes in logs
watch(() => dashboardStore.logs, () => {
  generateHeatmapData()
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
