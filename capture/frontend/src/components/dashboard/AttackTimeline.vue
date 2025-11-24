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

const API_KEY = 'capture_secure_key_2024'
const API_BASE = '/api'

interface TimelineData {
  timestamp: string
  count: number
  tools: Record<string, number>
  severities: Record<string, number>
}

const timeRange = ref('24')
const timelineData = ref<TimelineData[]>([])
const loading = ref(false)
const error = ref('')
const chartCanvas = ref<HTMLCanvasElement>()
let chartInstance: Chart | null = null
let refreshInterval: number | null = null

const hasData = computed(() => timelineData.value.length > 0)

const getInterval = () => {
  const hours = parseInt(timeRange.value)
  if (hours <= 1) return '5m'
  if (hours <= 6) return '30m'
  return '1h'
}

const fetchTimeline = async () => {
  try {
    loading.value = true
    error.value = ''
    
    const response = await fetch(
      `${API_BASE}/logs/timeline?hours=${timeRange.value}&interval=${getInterval()}`,
      { headers: { 'X-API-Key': API_KEY } }
    )
    
    if (!response.ok) throw new Error('Failed to fetch timeline data')
    
    const data = await response.json()
    timelineData.value = data.timeline || []
    
    await nextTick()
    updateChart()
  } catch (err: any) {
    error.value = err.message || 'Error loading timeline'
    console.error('Timeline fetch error:', err)
  } finally {
    loading.value = false
  }
}

const updateChart = () => {
  if (!chartCanvas.value || !hasData.value) return

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
        borderColor: '#EF4444',
        backgroundColor: 'rgba(239, 68, 68, 0.1)',
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointRadius: 4,
        pointHoverRadius: 6,
        pointBackgroundColor: '#EF4444',
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
          borderColor: '#EF4444',
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
  fetchTimeline()
  refreshInterval = window.setInterval(fetchTimeline, 30000) // Refresh every 30s
})

onUnmounted(() => {
  if (refreshInterval) clearInterval(refreshInterval)
  if (chartInstance) chartInstance.destroy()
})

watch(timeRange, fetchTimeline)
</script>

<style scoped>
.attack-timeline-card {
  height: 100%;
}

.timeline-chart {
  max-height: 350px;
}
</style>
