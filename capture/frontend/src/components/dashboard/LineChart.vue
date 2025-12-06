<template>
  <v-card elevation="2" rounded="lg" class="line-chart-card">
    <v-card-title class="d-flex align-center">
      <v-icon icon="mdi-chart-line" color="primary" class="mr-2" />
      <span class="text-h6 font-weight-bold">Attack Activity Timeline</span>
      <v-spacer />
      <v-btn-toggle v-model="timeRange" mandatory density="compact" variant="outlined">
        <v-btn value="1" size="small">1H</v-btn>
        <v-btn value="6" size="small">6H</v-btn>
        <v-btn value="24" size="small">24H</v-btn>
      </v-btn-toggle>
    </v-card-title>

    <v-card-text class="position-relative" style="min-height: 350px;">
      <!-- No Data State (Overlay) -->
      <div v-if="!hasData" class="d-flex flex-column align-center justify-center position-absolute w-100 h-100" style="top: 0; left: 0; z-index: 10; background: rgba(var(--v-theme-surface), 0.8);">
        <v-icon icon="mdi-chart-line-variant" size="64" color="grey-lighten-1" />
        <p class="text-body-2 text-medium-emphasis mt-4">No activity data available</p>
      </div>

      <!-- Chart Content (Always rendered to preserve instance) -->
      <div v-show="hasData || true" class="h-100">
        <!-- Legend -->
        <div class="chart-legend mb-4">
          <div class="legend-item">
            <v-icon icon="mdi-radar" size="small" color="error" class="mr-1" />
            <span class="text-caption">Security Tool Scans</span>
          </div>
          <div class="legend-item">
            <v-icon icon="mdi-console" size="small" color="warning" class="mr-1" />
            <span class="text-caption">Interactive Attacks</span>
          </div>
          <div class="legend-item">
            <v-icon icon="mdi-help-circle" size="small" color="info" class="mr-1" />
            <span class="text-caption">Unknown Tools</span>
          </div>
        </div>

        <canvas ref="chartCanvas" class="timeline-chart" />
      </div>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { useDashboardStore, type Log } from '@/stores/dashboard'
import { formatTime } from '@/utils/dateTime'
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

interface TimelineDataPoint {
  timestamp: string
  toolScans: number
  interactiveAttacks: number
  unknownTools: number
}

interface CategorizedLog extends Log {
  isToolScan: boolean
  isInteractive: boolean
  isUnknownTool: boolean
}

const timeRange = ref('24')
const timelineData = ref<TimelineDataPoint[]>([])
const chartCanvas = ref<HTMLCanvasElement>()
let chartInstance: Chart | null = null

const hasData = computed(() => timelineData.value.length > 0)

// Helper function to categorize logs
const categorizeLogs = (logs: Log[]): CategorizedLog[] => {
  return logs.map((log: Log) => {
    const attackTool = log.attack_tool || ''
    const method = log.method || ''
    const userAgent = log.user_agent || ''
    const path = log.path || ''
    
    // Security Tool Scans - explicit list of known security tools
    const knownTools = ['nmap', 'masscan', 'nikto', 'sqlmap', 'gobuster', 'dirbuster', 'wfuzz', 'burpsuite', 'hydra', 'metasploit', 'nuclei', 'bbot', 'amass', 'subfinder', 'httpx', 'ffuf', 'zap', 'acunetix', 'nessus', 'openvas', 'zgrab', 'wpscan', 'joomscan']
    const isToolScan = attackTool && knownTools.includes(attackTool.toLowerCase())
    
    // Interactive Attacks
    const isInteractive =
      method === 'POST' ||
      method === 'PUT' ||
      method === 'DELETE' ||
      !!log.form_data ||
      path.includes('upload') ||
      path.includes('shell') ||
      path.includes('cmd') ||
      path.includes('exec') ||
      path.includes('eval') ||
      userAgent.toLowerCase().includes('curl') ||
      userAgent.toLowerCase().includes('wget') ||
      userAgent.toLowerCase().includes('python') ||
      path.includes('<script') ||
      path.toLowerCase().includes('union') ||
      path.includes("' OR") ||
      path.includes('../../../')
    
    // Unknown Tools - attack_tool is 'unknown', empty, or doesn't exist
    const isUnknownTool = 
      !attackTool ||
      attackTool === 'unknown' ||
      attackTool === '' ||
      (!isToolScan && !isInteractive)
    
    return {
      ...log,
      isToolScan,
      isInteractive,
      isUnknownTool
    }
  })
}

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

  // Debug: log time range
  console.log(`📊 Chart filter: ${hours}H range, now=${now.toISOString()}, startTime=${startTime.toISOString()}`)
  console.log(`📊 Total logs: ${logs.length}`)
  
  // Filter logs by time range
  const filteredLogs = logs.filter(log => {
    const logTime = new Date(log.timestamp || log['@timestamp'] || Date.now())
    return logTime >= startTime && logTime <= now
  })
  
  console.log(`📊 Filtered logs for ${hours}H: ${filteredLogs.length}`)
  
  // Debug: if no logs in range, show the log timestamps to understand why
  if (filteredLogs.length === 0 && logs.length > 0) {
    const sampleLog = logs[0]
    const sampleTime = new Date(sampleLog.timestamp || sampleLog['@timestamp'] || Date.now())
    console.log(`📊 Sample log time: ${sampleTime.toISOString()} (${sampleLog.timestamp || sampleLog['@timestamp']})`)
    console.log(`📊 Time difference from now: ${Math.round((now.getTime() - sampleTime.getTime()) / 3600000)}h`)
  }

  if (filteredLogs.length === 0) {
    timelineData.value = []
    updateChart()
    return
  }

  // Categorize logs
  const categorizedLogs = categorizeLogs(filteredLogs)

  // Aggregate logs into time buckets
  const intervalMinutes = hours <= 1 ? 5 : (hours <= 6 ? 30 : 60)
  const buckets = new Map<string, TimelineDataPoint>()

  categorizedLogs.forEach((log: CategorizedLog) => {
    const timestamp = new Date(log.timestamp || log['@timestamp'] || Date.now())
    // Round down to nearest interval
    const bucketTime = new Date(
      Math.floor(timestamp.getTime() / (intervalMinutes * 60000)) * (intervalMinutes * 60000)
    )
    const key = bucketTime.toISOString()
    
    if (!buckets.has(key)) {
      buckets.set(key, {
        timestamp: key,
        toolScans: 0,
        interactiveAttacks: 0,
        unknownTools: 0
      })
    }
    
    const bucket = buckets.get(key)!
    
    if (log.isToolScan) bucket.toolScans++
    if (log.isInteractive) bucket.interactiveAttacks++
    if (log.isUnknownTool) bucket.unknownTools++
  })
  
  timelineData.value = Array.from(buckets.values())
    .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())

  updateChart()
}

const updateChart = () => {
  if (!chartCanvas.value) return
  
  const ctx = chartCanvas.value.getContext('2d')
  if (!ctx) return

  const labels = timelineData.value.map(d => formatTime(d.timestamp))

  const datasets = [
    {
      label: 'Security Tool Scans',
      data: timelineData.value.map(d => d.toolScans),
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
    },
    {
      label: 'Interactive Attacks',
      data: timelineData.value.map(d => d.interactiveAttacks),
      borderColor: '#F59E0B',
      backgroundColor: 'rgba(245, 158, 11, 0.1)',
      borderWidth: 2,
      fill: true,
      tension: 0.4,
      pointRadius: 4,
      pointHoverRadius: 6,
      pointBackgroundColor: '#F59E0B',
      pointBorderColor: '#fff',
      pointBorderWidth: 2
    },
    {
      label: 'Unknown Tools',
      data: timelineData.value.map(d => d.unknownTools),
      borderColor: '#3B82F6',
      backgroundColor: 'rgba(59, 130, 246, 0.1)',
      borderWidth: 2,
      fill: true,
      tension: 0.4,
      pointRadius: 4,
      pointHoverRadius: 6,
      pointBackgroundColor: '#3B82F6',
      pointBorderColor: '#fff',
      pointBorderWidth: 2
    }
  ]

  // If chart exists, update data only
  if (chartInstance) {
    chartInstance.data.labels = labels
    chartInstance.data.datasets = datasets
    chartInstance.update('none') // 'none' mode prevents animation on every update for better performance
    return
  }

  // Create new chart if it doesn't exist
  const config: ChartConfiguration = {
    type: 'line',
    data: {
      labels,
      datasets
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
          display: false // We use custom legend
        },
        tooltip: {
          backgroundColor: 'rgba(0, 0, 0, 0.8)',
          padding: 12,
          titleColor: '#fff',
          bodyColor: '#fff',
          borderColor: 'rgba(255, 255, 255, 0.2)',
          borderWidth: 1,
          displayColors: true,
          callbacks: {
            label: (context) => {
              return `${context.dataset.label}: ${context.parsed.y}`
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
.line-chart-card {
  height: 100%;
}

.timeline-chart {
  max-height: 350px;
}

.chart-legend {
  display: flex;
  gap: 24px;
  flex-wrap: wrap;
  justify-content: center;
  padding: 8px 0;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 4px;
}
</style>
