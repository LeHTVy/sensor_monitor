<template>
  <v-card elevation="2" rounded="lg" class="attack-timeline-card">
    <v-card-title class="d-flex align-center">
      <v-icon icon="mdi-chart-line" color="primary" class="mr-2" />
      <span class="text-h6 font-weight-bold">Attack Timeline</span>
      <v-spacer />
      <v-btn-toggle v-model="timeRange" mandatory density="compact" variant="outlined">
        <v-btn value="1" size="small">1H</v-btn>
        <v-btn value="6" size="small">6H</v-btn>
        <v-btn value="24" size="small">24H</v-btn>
      </v-btn-toggle>
    </v-card-title>

    <v-card-text>
      <div v-if="loading" class="text-center py-12">
        <v-progress-circular indeterminate color="primary" />
        <p class="text-caption mt-4">Loading timeline data...</p>
      </div>

      <div v-else-if="error" class="text-center py-12">
        <v-icon icon="mdi-alert-circle" color="error" size="48" />
        <p class="text-body-2 text-error mt-2">{{ error }}</p>
      </div>

      <div v-else-if="!hasData" class="text-center py-12">
        <v-icon icon="mdi-chart-line-variant" size="64" color="grey-lighten-1" />
        <p class="text-body-2 text-medium-emphasis mt-4">No attack data available</p>
      </div>

      <canvas v-else ref="chartCanvas" class="timeline-chart" />
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch, nextTick } from 'vue'
import { useDashboardStore } from '@/stores/dashboard'
import {
  Chart,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler,
  type ChartConfiguration
} from 'chart.js'

Chart.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, Filler)

const dashboardStore = useDashboardStore()

interface TimelineData {
  timestamp: string
  count: number
  tools: Record<string, number>
  severities: Record<string, number>
}

const timeRange = ref('24')
const timelineData = ref<TimelineData[]>([])
const chartCanvas = ref<HTMLCanvasElement>()
let chartInstance: Chart | null = null

const loading = computed(() => dashboardStore.loading)
const error = ref('') // Store doesn't expose error, but we can assume no error if logs are loaded
const hasData = computed(() => timelineData.value.length > 0)

const generateTimelineData = () => {
  const logs = dashboardStore.logs
  
  if (logs.length === 0) {
    timelineData.value = []
    updateChart()
    return
  }
  
  const hours = parseInt(timeRange.value)
  const now = new Date()
  const startTime = new Date(now.getTime() - hours * 60 * 60 * 1000)
  
  // Filter logs by time range
  const filteredLogs = logs.filter(log => {
    const logTime = new Date(log.timestamp || (log as any)['@timestamp'] || Date.now())
    return logTime >= startTime && logTime <= now
  })

  if (filteredLogs.length === 0) {
    timelineData.value = []
    updateChart()
    return
  }

  // Aggregate logs into time buckets
  const intervalMinutes = hours <= 1 ? 5 : (hours <= 6 ? 30 : 60)
  const buckets = new Map<string, TimelineData>()
  
  // Initialize buckets to ensure continuous line (optional, but looks better)
  // For now, let's just map the existing logs to avoid sparse array issues if not needed
  
  filteredLogs.forEach((log: any) => {
    const timestamp = new Date(log.timestamp || log['@timestamp'] || Date.now())
    // Round down to nearest interval
    const bucketTime = new Date(
      Math.floor(timestamp.getTime() / (intervalMinutes * 60000)) * (intervalMinutes * 60000)
    )
    const key = bucketTime.toISOString()
    
    if (!buckets.has(key)) {
      buckets.set(key, {
        timestamp: key,
        count: 0,
        tools: {},
        severities: {}
      })
    }
    
    const bucket = buckets.get(key)!
    bucket.count++
    
    // Track tools
    const tool = log.attack_tool || log.tool || 'unknown'
    bucket.tools[tool] = (bucket.tools[tool] || 0) + 1
    
    // Track severities
    const severity = log.threat_level || log.severity || 'low'
    bucket.severities[severity] = (bucket.severities[severity] || 0) + 1
  })
  
  timelineData.value = Array.from(buckets.values())
    .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
  
  updateChart()
}

const updateChart = () => {
  if (!chartCanvas.value) return
  
  // If no data, we might want to clear the chart or show empty state
  // The template handles !hasData, but if we have the canvas we can draw an empty chart or just return
  if (!hasData.value && chartInstance) {
     chartInstance.destroy()
     chartInstance = null
     return
  }
  
  const ctx = chartCanvas.value.getContext('2d')
  if (!ctx) return

  if (chartInstance) {
    chartInstance.destroy()
  }

  const labels = timelineData.value.map(d => {
    const date = new Date(d.timestamp)
    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
  })

  const data = timelineData.value.map(d => d.count)

  const config: ChartConfiguration = {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Attacks',
        data,
        borderColor: '#d5ba76',
        backgroundColor: 'rgba(213, 186, 118, 0.1)',
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointRadius: 4,
        pointHoverRadius: 6,
        pointBackgroundColor: '#d5ba76',
        pointBorderColor: '#fff',
        pointBorderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: {
        intersect: false,
        mode: 'index'
      },
      plugins: {
        legend: {
          display: false
        },
        tooltip: {
          backgroundColor: 'rgba(0, 0, 0, 0.8)',
          padding: 12,
          titleColor: '#fff',
          bodyColor: '#fff',
          borderColor: '#d5ba76',
          borderWidth: 1,
          displayColors: false,
          callbacks: {
            label: (context) => {
              const dataPoint = timelineData.value[context.dataIndex]
              const lines = [`Attacks: ${context.parsed.y}`]
              
              if (dataPoint.tools && Object.keys(dataPoint.tools).length > 0) {
                lines.push('', 'Top Tools:')
                Object.entries(dataPoint.tools)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 3)
                  .forEach(([tool, count]) => lines.push(`  ${tool}: ${count}`))
              }
              
              return lines
            }
          }
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          ticks: {
            precision: 0
          },
          grid: {
            color: 'rgba(0, 0, 0, 0.05)'
          }
        },
        x: {
          grid: {
            display: false
          }
        }
      }
    }
  }

  chartInstance = new Chart(ctx, config)
}

onMounted(() => {
  generateTimelineData()
})

onUnmounted(() => {
  if (chartInstance) chartInstance.destroy()
})

// Watch for changes in logs or timeRange
watch([() => dashboardStore.logs, timeRange], () => {
  generateTimelineData()
})
</script>

<style scoped>
.attack-timeline-card {
  height: 100%;
}

.timeline-chart {
  max-height: 350px;
}
</style>
