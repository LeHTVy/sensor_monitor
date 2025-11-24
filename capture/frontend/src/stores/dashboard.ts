import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { useAuthStore } from './auth'

export interface Log {
  timestamp: string
  src_ip: string
  dst_ip?: string
  type: string
  protocol?: string
  message?: string
  attack_tool?: string
  geoip?: {
    country: string
    city: string
    isp?: string
  }
  // Enrichment fields
  threat_level?: string
  threat_score?: number
  attack_techniques?: string[]
  osint?: {
    abuseipdb?: {
      abuseConfidenceScore: number
      usageType?: string
      isp?: string
    }
    shodan?: {
      ports?: number[]
      hostnames?: string[]
      vulns?: string[]
    }
    virustotal?: {
      malicious?: number
      suspicious?: number
      harmless?: number
    }
  }
}

export interface Stats {
  total_logs_received: number
  attack_logs: number
  honeypot_logs: number
  traffic_logs: number
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
    traffic_logs: 0
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
