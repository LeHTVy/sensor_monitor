<template>
  <v-card class="recon-chart-card" elevation="2">
    <v-card-text>
      <div class="d-flex align-center justify-space-between mb-3">
        <div class="text-overline">Top Recon Techniques (24h)</div>
        <v-chip size="x-small" color="primary" variant="outlined">
          {{ totalTechniques }} types
        </v-chip>
      </div>
      
      <div v-if="loading" class="text-center py-4">
        <v-progress-circular indeterminate size="24" />
      </div>
      
      <div v-else-if="techniques.length === 0" class="text-center text-medium-emphasis py-4">
        No recon activity detected
      </div>
      
      <div v-else class="techniques-list">
        <div 
          v-for="(tech, index) in techniques.slice(0, 5)" 
          :key="tech.name"
          class="technique-row mb-2"
        >
          <div class="d-flex justify-space-between align-center mb-1">
            <span class="text-caption font-weight-medium">{{ tech.name }}</span>
            <span class="text-caption text-medium-emphasis">{{ tech.count }}</span>
          </div>
          <div class="bar-container">
            <div 
              class="bar" 
              :style="{ width: `${tech.percentage}%` }"
              :class="getBarColor(index)"
            />
          </div>
        </div>
      </div>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'

interface Technique {
  name: string
  count: number
  percentage: number
}

const authStore = useAuthStore()
const loading = ref(true)
const techniques = ref<Technique[]>([])

const totalTechniques = computed(() => techniques.value.length)

// Map attack_tool to human-readable technique names
const toolToTechnique: Record<string, string> = {
  'nmap': 'Port Scan',
  'masscan': 'Port Scan',
  'rustscan': 'Port Scan',
  'nikto': 'Service Probe',
  'nuclei': 'Vuln Scanner',
  'sqlmap': 'SQL Injection',
  'gobuster': 'HTTP Crawler',
  'dirbuster': 'HTTP Crawler',
  'ffuf': 'HTTP Crawler',
  'dirb': 'HTTP Crawler',
  'wpscan': 'CMS Scanner',
  'joomscan': 'CMS Scanner',
  'hydra': 'Brute Force',
  'amass': 'DNS Recon',
  'subfinder': 'DNS Recon',
  'bbot': 'OSINT Recon',
  'web browser': 'Manual Browse'
}

function getBarColor(index: number): string {
  const colors = ['bar-primary', 'bar-warning', 'bar-info', 'bar-success', 'bar-secondary']
  return colors[index % colors.length]
}

async function fetchTechniques() {
  try {
    // Fetch logs to aggregate techniques from attack_tool field
    const response = await fetch('/api/logs?limit=1000', {
      headers: { 'X-API-Key': authStore.apiKey || '' }
    })
    
    if (response.ok) {
      const data = await response.json()
      const logs = data.logs || []
      
      // Aggregate techniques from attack_tool field in logs
      const techMap = new Map<string, number>()
      
      logs.forEach((log: any) => {
        const tool = log.attack_tool
        if (tool && tool !== 'unknown' && tool !== '') {
          const technique = toolToTechnique[tool.toLowerCase()] || tool
          techMap.set(technique, (techMap.get(technique) || 0) + 1)
        }
      })
      
      // Convert to array and sort
      const techArray = Array.from(techMap.entries())
        .map(([name, count]) => ({ name, count, percentage: 0 }))
        .sort((a, b) => b.count - a.count)
      
      // Calculate percentages
      const maxCount = techArray[0]?.count || 1
      techArray.forEach(tech => {
        tech.percentage = (tech.count / maxCount) * 100
      })
      
      techniques.value = techArray
    }
  } catch (error) {
    console.error('Failed to fetch techniques:', error)
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  fetchTechniques()
})
</script>

<style scoped>
.recon-chart-card {
  background: rgba(var(--v-theme-surface), 0.9);
  border: 1px solid rgba(var(--v-theme-primary), 0.2);
  min-height: 180px;
}

.techniques-list {
  max-height: 160px;
  overflow-y: auto;
}

.technique-row {
  padding: 4px 0;
}

.bar-container {
  height: 8px;
  background: rgba(var(--v-theme-on-surface), 0.1);
  border-radius: 4px;
  overflow: hidden;
}

.bar {
  height: 100%;
  border-radius: 4px;
  transition: width 0.5s ease;
}

.bar-primary { background: rgb(var(--v-theme-primary)); }
.bar-warning { background: rgb(var(--v-theme-warning)); }
.bar-info { background: rgb(var(--v-theme-info)); }
.bar-success { background: rgb(var(--v-theme-success)); }
.bar-secondary { background: rgb(var(--v-theme-secondary)); }
</style>
