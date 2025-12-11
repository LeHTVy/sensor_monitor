import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { useAuthStore } from './auth'

export interface Log {
  timestamp: string
  '@timestamp'?: string
  src_ip: string
  dst_ip?: string
  ip?: string
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
  json_body?: Record<string, unknown>
  raw_body?: string
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
  // File analysis fields (from honeypot)
  risk_level?: string
  risk_score?: number
  original_filename?: string
  filename?: string
  file_size?: number
  file_type?: {
    extension?: string
    magic?: string
    mime?: string
    extension_mismatch?: boolean
  }
  hashes?: {
    md5?: string
    sha1?: string
    sha256?: string
  }
  static_analysis?: {
    suspicious_patterns?: Record<string, string[]>
    [key: string]: unknown
  }
  event_type?: string
}

// SOC-focused stats from Elasticsearch
export interface Stats {
  // New SOC metrics
  high_severity_count: number
  unique_attackers: number
  top_attack_type: string
  most_targeted_port: number
  logs_in_period: number
  // Backwards compatibility
  total_logs_received: number
  last_received: string | null
  start_time: string
  uptime: number
  time_window_hours: number
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
    high_severity_count: 0,
    unique_attackers: 0,
    top_attack_type: 'None',
    most_targeted_port: 0,
    logs_in_period: 0,
    total_logs_received: 0,
    last_received: null,
    start_time: new Date().toISOString(),
    uptime: 0,
    time_window_hours: 24
  })
  const patterns = ref<Pattern[]>([])
  const currentFilter = ref<'all' | 'attack' | 'honeypot' | 'traffic'>('all')
  const loading = ref(false)
  const dateFrom = ref<string | null>(null)
  const dateTo = ref<string | null>(null)

  // Time period for stats (in hours)
  const statsPeriod = ref(24)  // Default: 24 hours

  // Known security/recon tools for categorization
  const KNOWN_SECURITY_TOOLS = [
    'nmap', 'masscan', 'nikto', 'sqlmap', 'gobuster', 'dirbuster',
    'wfuzz', 'burpsuite', 'hydra', 'metasploit', 'nuclei', 'bbot',
    'amass', 'subfinder', 'httpx', 'ffuf', 'zap', 'acunetix',
    'nessus', 'openvas', 'zgrab', 'wpscan', 'joomscan', 'dirb',
    'fierce', 'theharvester', 'whatweb', 'recon_tool', 'scanner',
    'naabu', 'shodan', 'censys', 'rustscan'
  ]

  // Interactive/browser attack tools
  const INTERACTIVE_TOOLS = ['web browser', 'browser', 'chrome', 'firefox', 'safari', 'edge']

  // Calculate accurate stats from actual logs (based on attack_tool field)
  const calculatedStats = computed(() => {
    const allLogs = logs.value

    let toolScans = 0
    let interactiveAttacks = 0
    let unknownTools = 0

    allLogs.forEach(log => {
      const tool = (log.attack_tool || '').toLowerCase().trim()
      const method = (log.method || '').toUpperCase()
      const path = (log.path || '').toLowerCase()

      // Category 1: Security Tool Scans
      // If attack_tool matches known security tools
      if (tool && KNOWN_SECURITY_TOOLS.some(knownTool => tool.includes(knownTool))) {
        toolScans++
        return
      }

      // Category 2: Interactive Attacks
      if (tool && INTERACTIVE_TOOLS.some(interactiveTool => tool.includes(interactiveTool))) {
        interactiveAttacks++
        return
      }

      const isInteractiveMethod = (
        method === 'POST' ||
        method === 'PUT' ||
        method === 'DELETE'
      )
      const isInteractivePath = (
        path.includes('/login') ||
        path.includes('/admin') ||
        path.includes('/auth') ||
        path.includes('/upload') ||
        path.includes('/console') ||
        path.includes('/shell') ||
        path.includes('/api')
      )

      if (isInteractiveMethod && isInteractivePath && !tool) {
        interactiveAttacks++
        return
      }

      if (log.form_data) {
        interactiveAttacks++
        return
      }

      unknownTools++
    })

    return {
      toolScans,
      interactiveAttacks,
      unknownTools,
      totalLogs: stats.value.total_logs_received || allLogs.length
    }
  })

  async function loadStats() {
    if (!authStore.isLoggedIn || !authStore.apiKey) return

    try {
      const response = await fetch(`/api/stats?hours=${statsPeriod.value}`, {
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
      params.append('limit', '2000')

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

  function setStatsPeriod(hours: number) {
    statsPeriod.value = hours
    loadStats()
  }

  return {
    logs,
    stats,
    patterns,
    currentFilter,
    loading,
    dateFrom,
    dateTo,
    statsPeriod,
    calculatedStats,
    loadStats,
    loadLogs,
    loadPatterns,
    setFilter,
    setDateFilter,
    clearDateFilter,
    setStatsPeriod,
    loadAllData
  }
})
