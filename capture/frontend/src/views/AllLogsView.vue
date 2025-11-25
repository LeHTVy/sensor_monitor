<template>
  <v-app>
    <Navbar />
    
    <v-main>
      <v-container fluid class="pa-0">
        <v-row no-gutters>
          <!-- Left Sidebar: Threat Capsules -->
          <v-col cols="12" md="3" class="threat-sidebar">
            <div class="pa-4">
              <div class="mb-2">
                <h2 class="text-h6 font-weight-bold">Honeypot Threat Feed</h2>
                <p class="text-caption text-medium-emphasis">Threat Capsules</p>
              </div>
              
              <v-text-field
                v-model="search"
                prepend-inner-icon="mdi-magnify"
                placeholder="Search logs..."
                density="compact"
                variant="outlined"
                class="mb-3"
                hide-details
              />
              
              <div class="capsules-list">
                <ThreatCapsule
                  v-for="log in filteredLogs"
                  :key="log.id"
                  :log="log"
                  :selected="selectedLog?.id === log.id"
                  @click="selectLog(log)"
                />
                
                <div v-if="filteredLogs.length === 0" class="text-center py-8 text-medium-emphasis">
                  <v-icon size="48" class="mb-2">mdi-alert-circle-outline</v-icon>
                  <p class="text-body-2">No logs found</p>
                </div>
                
                <div v-if="loading" class="text-center py-8">
                  <v-progress-circular indeterminate color="primary" />
                  <p class="text-caption mt-2">Loading threats...</p>
                </div>
              </div>
            </div>
          </v-col>
          
          <!-- Right Panel: Threat Analysis -->
          <v-col cols="12" md="9" class="analysis-panel">
            <ThreatAnalysisPanel :log="selectedLog" />
          </v-col>
        </v-row>
      </v-container>
    </v-main>

    <Footer />
  </v-app>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import Navbar from '@/components/Navbar.vue'
import Footer from '@/components/Footer.vue'
import ThreatCapsule from '@/components/alllogs/ThreatCapsule.vue'
import ThreatAnalysisPanel from '@/components/alllogs/ThreatAnalysisPanel.vue'

const API_KEY = 'capture_secure_key_2024'
const API_BASE = '/api'

const search = ref('')
const logs = ref<any[]>([])
const selectedLog = ref<any>(null)
const loading = ref(false)

async function fetchLogs() {
  try {
    loading.value = true
    const response = await fetch(
      `${API_BASE}/logs?limit=100`,
      { headers: { 'X-API-Key': API_KEY } }
    )
    
    if (response.ok) {
      const data = await response.json()
      logs.value = data.logs || []
      
      // Auto-select first log
      if (logs.value.length > 0 && !selectedLog.value) {
        selectedLog.value = logs.value[0]
      }
    }
  } catch (error) {
    console.error('Error fetching logs:', error)
  } finally {
    loading.value = false
  }
}

const filteredLogs = computed(() => {
  if (!search.value) return logs.value
  
  const searchLower = search.value.toLowerCase()
  return logs.value.filter(log => 
    log.src_ip?.toLowerCase().includes(searchLower) ||
    log.ip?.toLowerCase().includes(searchLower) ||
    log.attack_tool?.toLowerCase().includes(searchLower) ||
    log.geoip?.country?.toLowerCase().includes(searchLower) ||
    log.category?.toLowerCase().includes(searchLower)
  )
})

function selectLog(log: any) {
  selectedLog.value = log
}

onMounted(() => {
  fetchLogs()
})
</script>

<style scoped>
.threat-sidebar {
  background: rgb(var(--v-theme-surface));
  border-right: 1px solid rgba(var(--v-theme-primary), 0.1);
  height: calc(100vh - 64px);
  overflow-y: auto;
}

.capsules-list {
  max-height: calc(100vh - 250px);
  overflow-y: auto;
}

.analysis-panel {
  height: calc(100vh - 64px);
  overflow-y: auto;
}

/* Custom scrollbar */
.threat-sidebar::-webkit-scrollbar,
.capsules-list::-webkit-scrollbar,
.analysis-panel::-webkit-scrollbar {
  width: 6px;
}

.threat-sidebar::-webkit-scrollbar-thumb,
.capsules-list::-webkit-scrollbar-thumb,
.analysis-panel::-webkit-scrollbar-thumb {
  background: rgba(var(--v-theme-primary), 0.3);
  border-radius: 3px;
}
</style>
