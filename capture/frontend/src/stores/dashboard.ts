import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { useAuthStore } from './auth'

export interface Log {
  id?: string
  timestamp: string
  type: string
  src_ip: string
  dst_ip?: string
  message?: string
  attack_tool?: string
  attack_technique?: string[]
  geoip?: {
    country: string
    city: string
  }
}

export interface Stats {
  total_logs_received: number
  attack_logs: number
  honeypot_logs: number
  traffic_logs: number
}

export interface Pattern {
  tool: string
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
      const url = currentFilter.value === 'all'
        ? '/api/logs'
        : `/api/logs?type=${currentFilter.value}`

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
    statCards,
    loadStats,
    loadLogs,
    loadPatterns,
    setFilter,
    loadAllData
  }
})
