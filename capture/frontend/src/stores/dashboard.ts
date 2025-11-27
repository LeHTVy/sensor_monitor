import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { useAuthStore } from './auth'

export interface Log {
  timestamp: string
  '@timestamp'?: string // Elasticsearch standard timestamp field
  src_ip: string
  dst_ip?: string
  ip?: string // Alternative field name used by some logs
  type: string
  protocol?: string
  message?: string
  attack_tool?: string
  geoip?: {
    country: string
    city: string
    isp?: string
    org?: string
    lat?: number
    lon?: number
    timezone?: string
    region?: string
    postal?: string
  }
  // Enrichment fields
  threat_level?: string
  threat_score?: number
  attack_techniques?: string[]
  osint?: {
    abuseipdb?: {
      abuseConfidenceScore?: number
      abuse_confidence_score?: number
      usageType?: string
      isp?: string
    }
    shodan?: {
      ports?: number[]
      hostnames?: string[]
      vulns?: string[]
      org?: string
      isp?: string
    }
    virustotal?: {
      malicious?: number
      suspicious?: number
      harmless?: number
    }
    enriched_at?: string
  }
  // Additional fields from API
  id?: string
  attack_tool_info?: Record<string, unknown>
  attack_technique?: string[]
  os_info?: Record<string, unknown>
  method?: string
  path?: string
  url?: string
  user_agent?: string
  headers?: Record<string, unknown>
  args?: Record<string, unknown>
  form_data?: Record<string, unknown>
  port?: number
  kafka_topic?: string
  '@ingested_at'?: string
  llm_analysis?: {
    intent: string
    recommendations: string[]
    severity?: string
    confidence?: number
  } | null
  defense_playbook?: Record<string, unknown> | null
  // Network log fields
  src_port?: number
  dst_port?: number
  flags?: string | number
  size?: number
  payload?: string
  body?: string | Record<string, unknown>
}

export interface Stats {
  total_logs_received: number
  attack_logs: number
  honeypot_logs: number
  traffic_logs: number
  tool_scan_logs: number
  interactive_attack_logs: number
  normal_browsing_logs: number
}

export interface Pattern {
  pattern: string
  count: number
  first_seen: string
  last_seen: string
}

export const useDashboardStore = defineStore('dashboard', () => {
  const authStore = useAuthStore()

  const logs = ref<Log[]>([])
  const stats = ref<Stats>({
    total_logs_received: 0,
    attack_logs: 0,
    honeypot_logs: 0,
    traffic_logs: 0,
    tool_scan_logs: 0,
    interactive_attack_logs: 0,
    normal_browsing_logs: 0
  })
  const patterns = ref<Pattern[]>([])
  const currentFilter = ref<'all' | 'attack' | 'honeypot' | 'traffic'>('all')
  const loading = ref(false)
  const dateFrom = ref<string | null>(null)
  const dateTo = ref<string | null>(null)

  const statCards = computed(() => [
    { title: 'Total Logs', value: stats.value.total_logs_received },
    { title: 'Attacks', value: stats.value.attack_logs },
    { title: 'Honeypot', value: stats.value.honeypot_logs },
    { title: 'Traffic', value: stats.value.traffic_logs }
  ])

  async function loadStats() {
    if (!authStore.isLoggedIn || !authStore.apiKey) return

    try {
      const response = await fetch('/api/stats', {
        method: 'GET',
        headers: {
          'X-API-Key': authStore.apiKey,
          'Content-Type': 'application/json'
        }
      })

      if (response.ok) {
        const data = await response.json()
        stats.value = data.stats
      } else if (response.status === 401) {
        authStore.logout()
      }
    } catch (error) {
      console.error('Error loading stats:', error)
    }
  }

  async function loadLogs() {
    if (!authStore.isLoggedIn || !authStore.apiKey) return

    try {
      const params = new URLSearchParams()
      if (currentFilter.value !== 'all') {
        params.append('type', currentFilter.value)
      }
      if (dateFrom.value) {
        params.append('date_from', dateFrom.value)
      }
      if (dateTo.value) {
        params.append('date_to', dateTo.value)
      }
      params.append('limit', '1000')  // Tăng limit để hiển thị nhiều logs hơn

      const url = `/api/logs?${params.toString()}`

      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'X-API-Key': authStore.apiKey,
          'Content-Type': 'application/json'
        }
      })

      if (response.ok) {
        const data = await response.json()
        logs.value = data.logs || []
      } else if (response.status === 401) {
        authStore.logout()
      }
    } catch (error) {
      console.error('Error loading logs:', error)
    }
  }

  function setDateFilter(from: string | null, to: string | null) {
    dateFrom.value = from
    dateTo.value = to
    loadLogs()
  }

  function clearDateFilter() {
    dateFrom.value = null
    dateTo.value = null
    loadLogs()
  }

  async function loadPatterns() {
    if (!authStore.isLoggedIn || !authStore.apiKey) return

    try {
      const response = await fetch('/api/attack-patterns', {
        method: 'GET',
        headers: {
          'X-API-Key': authStore.apiKey,
          'Content-Type': 'application/json'
        }
      })

      if (response.ok) {
        const data = await response.json()
        patterns.value = data.patterns || []
      } else if (response.status === 401) {
        authStore.logout()
      }
    } catch (error) {
      console.error('Error loading patterns:', error)
    }
  }

  function setFilter(filter: 'all' | 'attack' | 'honeypot' | 'traffic') {
    currentFilter.value = filter
    loadLogs()
  }

  async function loadAllData() {
    loading.value = true
    try {
      await Promise.all([
        loadStats(),
        loadLogs(),
        loadPatterns()
      ])
    } finally {
      loading.value = false
    }
  }

  return {
    logs,
    stats,
    patterns,
    currentFilter,
    loading,
    dateFrom,
    dateTo,
    statCards,
    loadStats,
    loadLogs,
    loadPatterns,
    setFilter,
    setDateFilter,
    clearDateFilter,
    loadAllData
  }
})
