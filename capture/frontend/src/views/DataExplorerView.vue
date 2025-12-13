<template>
  <v-app>
    <Navbar />
    <v-main>
      <v-container fluid class="data-explorer fill-height pa-0">
        <v-row no-gutters class="fill-height">
      <!-- Sidebar Filters -->
      <v-col cols="12" md="3" lg="2" class="filter-sidebar border-e">
        <div class="pa-4">
          <h2 class="text-h6 font-weight-bold mb-4">Filters</h2>
          
          <!-- Time Range -->
          <v-select
            v-model="timeRange"
            label="Time Range"
            :items="timeRanges"
            item-title="text"
            item-value="value"
            variant="outlined"
            density="compact"
            class="mb-4"
            @update:model-value="applyFilters"
          ></v-select>

          <!-- Log Type -->
          <v-select
            v-model="filters.type"
            label="Log Type"
            :items="['All', 'Attack', 'Honeypot', 'Traffic']"
            variant="outlined"
            density="compact"
            class="mb-4"
            @update:model-value="applyFilters"
          ></v-select>

          <!-- Search -->
          <v-text-field
            v-model="filters.search"
            label="Search (IP, Tool, Path)"
            prepend-inner-icon="mdi-magnify"
            variant="outlined"
            density="compact"
            hide-details
            class="mb-4"
            @keyup.enter="applyFilters"
          ></v-text-field>

          <!-- Advanced Filters -->
          <v-expansion-panels variant="accordion" class="mb-4">
            <v-expansion-panel title="Advanced">
              <v-expansion-panel-text>
                <v-text-field
                  v-model="filters.country"
                  label="Country"
                  variant="outlined"
                  density="compact"
                  class="mb-2"
                ></v-text-field>
                <v-text-field
                  v-model="filters.port"
                  label="Port"
                  type="number"
                  variant="outlined"
                  density="compact"
                  class="mb-2"
                ></v-text-field>
              </v-expansion-panel-text>
            </v-expansion-panel>
          </v-expansion-panels>

          <v-btn block color="primary" @click="applyFilters" :loading="loading">
            Apply Filters
          </v-btn>
          <v-btn block variant="text" color="error" class="mt-2" @click="resetFilters">
            Reset
          </v-btn>
        </div>
      </v-col>

      <!-- Main Content -->
      <v-col cols="12" md="9" lg="10" class="d-flex flex-column h-100">
        <!-- Toolbar -->
        <div class="d-flex align-center pa-4 border-b bg-surface">
          <h1 class="text-h5 font-weight-bold">Data Explorer</h1>
          <v-spacer></v-spacer>
          
          <!-- Auto-refresh toggle -->
          <v-switch
            v-model="autoRefresh"
            label="Auto-refresh"
            color="primary"
            density="compact"
            hide-details
            class="mr-4"
            @update:model-value="toggleAutoRefresh"
          ></v-switch>
          
          <v-btn prepend-icon="mdi-download" variant="outlined" class="mr-2" @click="exportData">
            Export CSV
          </v-btn>
          <v-btn 
            icon 
            variant="text" 
            @click="refreshData"
            :loading="loading"
          >
            <v-icon>mdi-refresh</v-icon>
          </v-btn>
        </div>

        <!-- Visualization (Histogram) -->
        <div class="visualization-area pa-4 border-b" style="min-height: 250px; max-height: 250px;">
          <canvas ref="chartCanvas" style="max-height: 200px;"></canvas>
        </div>

        <!-- Data Grid -->
        <div class="flex-grow-1 overflow-auto">
          <v-data-table
            :headers="headers"
            :items="logs"
            :loading="loading"
            v-model:items-per-page="itemsPerPage"
            hover
            density="compact"
            class="h-100"
            fixed-header
          >
            <!-- Custom Columns -->
            <template v-slot:item.timestamp="{ item }">
              {{ formatDate(item.timestamp) }}
            </template>
            
            <template v-slot:item.type="{ item }">
              <v-chip
                size="x-small"
                :color="getTypeColor(item.type)"
                variant="flat"
              >
                {{ item.type.toUpperCase() }}
              </v-chip>
            </template>

            <template v-slot:item.threat_score="{ item }">
              <div v-if="item.threat_score" class="d-flex align-center">
                <v-progress-linear
                  :model-value="item.threat_score"
                  :color="getScoreColor(item.threat_score)"
                  height="4"
                  rounded
                  style="width: 50px"
                  class="mr-2"
                ></v-progress-linear>
                <span class="text-caption">{{ item.threat_score }}</span>
              </div>
              <span v-else class="text-caption text-medium-emphasis">-</span>
            </template>

            <!-- Expandable Row -->
            <template v-slot:expanded-row="{ columns, item }">
              <tr>
                <td :colspan="columns.length" class="pa-4 bg-surface-variant">
                  <v-row>
                    <!-- POST Form Data -->
                    <v-col v-if="item.form_data && Object.keys(item.form_data).length > 0" cols="12" md="6">
                      <div class="detail-section">
                        <v-icon size="small" color="warning" class="mr-1">mdi-form-textbox</v-icon>
                        <strong>POST Form Data:</strong>
                        <div class="code-block mt-2 pa-2 rounded bg-warning-lighten-5">
                          <div v-for="(value, key) in item.form_data" :key="key" class="mb-1">
                            <span class="text-primary font-weight-bold">{{ key }}:</span> 
                            <span class="text-error">{{ value }}</span>
                          </div>
                        </div>
                      </div>
                    </v-col>

                    <!-- JSON Body -->
                    <v-col v-if="item.json_body && Object.keys(item.json_body).length > 0" cols="12" md="6">
                      <div class="detail-section">
                        <v-icon size="small" color="info" class="mr-1">mdi-code-json</v-icon>
                        <strong>JSON Body:</strong>
                        <pre class="code-block mt-2 pa-2 rounded bg-info-lighten-5">{{ JSON.stringify(item.json_body, null, 2) }}</pre>
                      </div>
                    </v-col>

                    <!-- Query Args -->
                    <v-col v-if="item.args && Object.keys(item.args).length > 0" cols="12" md="6">
                      <div class="detail-section">
                        <v-icon size="small" color="success" class="mr-1">mdi-help-circle</v-icon>
                        <strong>Query Parameters:</strong>
                        <div class="code-block mt-2 pa-2 rounded bg-success-lighten-5">
                          <div v-for="(value, key) in item.args" :key="key" class="mb-1">
                            <span class="text-primary font-weight-bold">{{ key }}:</span> 
                            <span>{{ value }}</span>
                          </div>
                        </div>
                      </div>
                    </v-col>

                    <!-- Raw Body -->
                    <v-col v-if="item.raw_body && item.raw_body.length > 0" cols="12" md="6">
                      <div class="detail-section">
                        <v-icon size="small" color="error" class="mr-1">mdi-file-document</v-icon>
                        <strong>Raw Body:</strong>
                        <pre class="code-block mt-2 pa-2 rounded bg-error-lighten-5">{{ item.raw_body }}</pre>
                      </div>
                    </v-col>

                    <!-- Headers -->
                    <v-col cols="12" md="6">
                      <div class="detail-section">
                        <v-icon size="small" class="mr-1">mdi-web</v-icon>
                        <strong>Headers:</strong>
                        <pre class="code-block mt-2 pa-2 rounded">{{ JSON.stringify(item.headers, null, 2) }}</pre>
                      </div>
                    </v-col>

                    <!-- GeoIP & OSINT -->
                    <v-col cols="12" md="6">
                      <div class="detail-section">
                        <v-icon size="small" color="purple" class="mr-1">mdi-earth</v-icon>
                        <strong>GeoIP:</strong>
                        <pre class="code-block mt-2 pa-2 rounded">{{ JSON.stringify(item.geoip, null, 2) }}</pre>
                      </div>
                    </v-col>
                  </v-row>
                </td>
              </tr>
            </template>
          </v-data-table>
        </div>
      </v-col>
    </v-row>
  </v-container>
    </v-main>
  </v-app>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { useDashboardStore } from '@/stores/dashboard'
import { useAuthStore } from '@/stores/auth'
import { formatDateTime } from '@/utils/dateTime'
import Navbar from '@/components/Navbar.vue'
import Chart from 'chart.js/auto'
import 'chartjs-adapter-date-fns'

const dashboardStore = useDashboardStore()
const authStore = useAuthStore()

// State
const loading = ref(false)
const logs = ref<any[]>([])
const chartCanvas = ref<HTMLCanvasElement | null>(null)
let chartInstance: any = null
const itemsPerPage = ref(25)
const autoRefresh = ref(false)
let refreshInterval: ReturnType<typeof setInterval> | null = null

// Filters
const timeRange = ref('24h')
const timeRanges = [
  { text: 'Last 1 Hour', value: '1h' },
  { text: 'Last 6 Hours', value: '6h' },
  { text: 'Last 24 Hours', value: '24h' },
  { text: 'Last 7 Days', value: '7d' },
  { text: 'All Time', value: 'all' }
]

const filters = ref({
  type: 'All',
  search: '',
  country: '',
  port: ''
})

// Table Headers
const headers = [
  { title: 'Time', key: 'timestamp', width: '180px' },
  { title: 'Type', key: 'type', width: '100px' },
  { title: 'Source IP', key: 'src_ip', width: '140px' },
  { title: 'Country', key: 'geoip.country', width: '120px' },
  { title: 'Tool', key: 'attack_tool', width: '120px' },
  { title: 'Path/Message', key: 'path', width: '300px' },
  { title: 'Score', key: 'threat_score', width: '100px' },
]

// Methods
function formatDate(dateStr: string) {
  return formatDateTime(dateStr)
}

function getTypeColor(type: string) {
  switch (type) {
    case 'attack': return 'error'
    case 'honeypot': return 'warning'
    case 'traffic': return 'info'
    default: return 'grey'
  }
}

function getScoreColor(score: number) {
  if (score >= 75) return 'error'
  if (score >= 50) return 'warning'
  return 'success'
}

async function applyFilters() {
  loading.value = true
  
  let dateFrom = null
  const now = new Date()
  if (timeRange.value !== 'all') {
    const hours = parseInt(timeRange.value)
    if (timeRange.value.includes('d')) {
      dateFrom = new Date(now.getTime() - parseInt(timeRange.value) * 24 * 60 * 60 * 1000)
    } else {
      dateFrom = new Date(now.getTime() - parseInt(timeRange.value) * 60 * 60 * 1000)
    }
  }

  try {
    const params = new URLSearchParams()
    params.append('limit', '1000') // Reduced to prevent crashes with real-time data 
    
    if (dateFrom) params.append('date_from', dateFrom.toISOString())
    if (filters.value.type !== 'All') params.append('type', filters.value.type.toLowerCase())
    
    const response = await fetch(`/api/logs?${params.toString()}`, {
      headers: { 'X-API-Key': authStore.apiKey || '' } 
    })
    
    if (response.ok) {
      const data = await response.json()
      let fetchedLogs = data.logs || []
      
      // Client-side filtering for advanced fields
      if (filters.value.search) {
        const term = filters.value.search.toLowerCase()
        fetchedLogs = fetchedLogs.filter((l: any) => 
          (l.src_ip && l.src_ip.includes(term)) ||
          (l.attack_tool && l.attack_tool.toLowerCase().includes(term)) ||
          (l.path && l.path.toLowerCase().includes(term))
        )
      }
      
      if (filters.value.country) {
        fetchedLogs = fetchedLogs.filter((l: any) => 
          l.geoip?.country?.toLowerCase().includes(filters.value.country.toLowerCase())
        )
      }
      
      if (filters.value.port) {
        fetchedLogs = fetchedLogs.filter((l: any) => 
          l.dst_port == filters.value.port
        )
      }
      
      logs.value = fetchedLogs
      updateChart()
    }
  } catch (e) {
    console.error(e)
  } finally {
    loading.value = false
  }
}

function resetFilters() {
  timeRange.value = '24h'
  filters.value = {
    type: 'All',
    search: '',
    country: '',
    port: ''
  }
  applyFilters()
}

function updateChart() {
  if (!chartCanvas.value) return
  
  // Destroy existing
  if (chartInstance) {
    chartInstance.destroy()
  }
  
  const buckets: Record<string, number> = {}
  logs.value.forEach(log => {
    const date = new Date(log.timestamp || log['@timestamp'])
    const key = new Date(date.setMinutes(0, 0, 0)).toISOString() 
    buckets[key] = (buckets[key] || 0) + 1
  })
  
  const sortedKeys = Object.keys(buckets).sort()
  const data = sortedKeys.map(k => buckets[k])
  
  chartInstance = new Chart(chartCanvas.value, {
    type: 'bar',
    data: {
      labels: sortedKeys.map(k => new Date(k)),
      datasets: [{
        label: 'Log Volume',
        data: data,
        backgroundColor: 'rgba(59, 130, 246, 0.5)',
        borderColor: 'rgb(59, 130, 246)',
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          type: 'time',
          time: { 
            unit: 'hour',
            displayFormats: {
              hour: 'HH:mm'
            },
            tooltipFormat: 'dd/MM/yyyy HH:mm'
          },
          grid: { display: false },
          ticks: {
            callback: function(value: any) {
              const date = new Date(value)
              // Convert to Vietnam time (UTC+7)
              const vnTime = new Date(date.getTime() + (7 * 60 * 60 * 1000))
              return vnTime.toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit', hour12: false })
            }
          }
        },
        y: {
          beginAtZero: true,
          grid: { color: 'rgba(0,0,0,0.05)' }
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            title: function(context: any) {
              const date = new Date(context[0].parsed.x)
              // Format in Vietnam timezone
              return date.toLocaleString('vi-VN', { timeZone: 'Asia/Ho_Chi_Minh' })
            }
          }
        }
      }
    }
  })
}

function exportData() {
  const csvContent = "data:text/csv;charset=utf-8," 
    + "Timestamp,Type,Source IP,Country,Tool,Path\n"
    + logs.value.map(row => {
        return `${row.timestamp},${row.type},${row.src_ip},${row.geoip?.country || ''},${row.attack_tool || ''},"${row.path || ''}"`
      }).join("\n")
      
  const encodedUri = encodeURI(csvContent)
  const link = document.createElement("a")
  link.setAttribute("href", encodedUri)
  link.setAttribute("download", "sensor_logs_export.csv")
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
}

function refreshData() {
  applyFilters()
}

function toggleAutoRefresh(enabled: boolean) {
  if (enabled) {
    // Start auto-refresh every 30 seconds
    refreshInterval = setInterval(() => {
      applyFilters()
    }, 30000)
  } else {
    // Stop auto-refresh
    if (refreshInterval) {
      clearInterval(refreshInterval)
      refreshInterval = null
    }
  }
}

onMounted(() => {
  applyFilters()
})

// Cleanup on unmount
onUnmounted(() => {
  if (refreshInterval) {
    clearInterval(refreshInterval)
  }
  if (chartInstance) {
    chartInstance.destroy()
  }
})
</script>

<style scoped>
.filter-sidebar {
  background: rgb(var(--v-theme-surface));
  height: 100%;
  overflow-y: auto;
}

.code-block {
  font-family: monospace;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
}
</style>
