<template>
  <v-dialog v-model="dialogVisible" max-width="900" persistent>
    <v-card>
      <v-card-title class="d-flex align-center justify-space-between pa-4 bg-primary">
        <div>
          <h3 class="text-h6">Black Box Reconnaissance</h3>
          <p class="text-caption">Target: {{ attacker?.ip }}</p>
        </div>
        <v-btn icon="mdi-close" variant="text" @click="close" v-if="status === 'completed' || status === 'error'"></v-btn>
      </v-card-title>

      <v-card-text class="pa-4">
        <!-- Target Info -->
        <v-alert v-if="reconId === 'pending'" type="info" variant="tonal" class="mb-4">
          <div class="d-flex align-center">
            <v-progress-circular indeterminate size="24" class="mr-3"></v-progress-circular>
            <span>Starting reconnaissance on <strong>{{ attacker?.ip }}</strong>...</span>
          </div>
        </v-alert>

        <v-alert v-else type="info" variant="tonal" class="mb-4">
          <div><strong>IP:</strong> {{ attacker?.ip }}</div>
          <div><strong>Country:</strong> {{ attacker?.country }}</div>
          <div><strong>Total Attacks:</strong> {{ attacker?.total_attacks }}</div>
          <div><strong>Threat Score:</strong> {{ attacker?.max_threat_score }}</div>
        </v-alert>

        <!-- Overall Progress (hide when pending) -->
        <div v-if="reconId !== 'pending'" class="mb-4">
          <div class="d-flex justify-space-between mb-2">
            <span class="text-subtitle-2">Overall Progress</span>
            <span class="text-caption">{{ completedTools }}/{{ totalTools }} tools completed</span>
          </div>
          <v-progress-linear
            :model-value="(completedTools / totalTools) * 100"
            :color="progressColor"
            height="8"
            rounded
          ></v-progress-linear>
        </div>

        <!-- Tool Status Timeline (hide when pending) -->
        <div v-if="reconId !== 'pending'" class="tool-timeline mb-4">
          <div
            v-for="tool in tools"
            :key="tool.name"
            class="tool-item d-flex align-center mb-3"
          >
            <v-icon
              :color="getToolIconColor(tool.status)"
              :icon="getToolIcon(tool.status)"
              size="large"
            ></v-icon>
            
            <div class="flex-grow-1 ml-4">
              <div class="d-flex justify-space-between">
                <span class="font-weight-medium">{{ tool.label }}</span>
                <v-chip
                  :color="getToolChipColor(tool.status)"
                  size="small"
                  variant="flat"
                >
                  {{ tool.status }}
                </v-chip>
              </div>
              
              <div v-if="tool.status === 'running'" class="mt-2">
                <v-progress-linear indeterminate color="primary"></v-progress-linear>
              </div>
              
              <div v-if="tool.output && showOutput === tool.name" class="mt-2">
                <pre class="output-terminal">{{ tool.output }}</pre>
              </div>
              
              <v-btn
                v-if="tool.output"
                size="small"
                variant="text"
                @click="toggleOutput(tool.name)"
                class="mt-1"
              >
                {{ showOutput === tool.name ? 'Hide' : 'Show' }} Output
              </v-btn>
            </div>
          </div>
        </div>

        <!-- Error Message -->
        <v-alert v-if="status === 'error' && errorMessage" type="error" variant="tonal" class="mb-4">
          <strong>Error:</strong> {{ errorMessage }}
        </v-alert>

        <!-- Report Download Section -->
        <div v-if="status === 'completed'" class="mt-4">
          <v-divider class="mb-4"></v-divider>
          <h4 class="text-subtitle-1 mb-3">Download Report</h4>
          <div class="d-flex gap-3">
            <v-btn
              @click="downloadReport('docx')"
              color="primary"
              prepend-icon="mdi-file-word"
              :loading="downloadingDocx"
            >
              Download DOCX
            </v-btn>
            <v-btn
              @click="downloadReport('pdf')"
              color="error"
              prepend-icon="mdi-file-pdf-box"
              :loading="downloadingPdf"
            >
              Download PDF
            </v-btn>
          </div>
        </div>
      </v-card-text>

      <v-card-actions class="pa-4 border-t">
        <v-spacer></v-spacer>
        <v-btn
          v-if="status === 'completed' || status === 'error'"
          @click="close"
          color="primary"
        >
          Close
        </v-btn>
        <v-btn
          v-else
          @click="close"
          variant="outlined"
          color="error"
          disabled
        >
          Scanning in progress...
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { ref, computed, watch, onUnmounted } from 'vue'
import { useAttackersStore } from '@/stores/attackers'

const props = defineProps({
  modelValue: {
    type: Boolean,
    required: true
  },
  attacker: {
    type: Object,
    required: true
  },
  reconId: {
    type: String,
    required: true
  }
})

const emit = defineEmits(['update:modelValue', 'close'])

const attackersStore = useAttackersStore()

// Data
const showOutput = ref('')
const downloadingDocx = ref(false)
const downloadingPdf = ref(false)
const pollInterval = ref(null)

// Computed
const dialogVisible = computed({
  get: () => props.modelValue,
  set: (value) => emit('update:modelValue', value)
})

const reconStatus = computed(() => attackersStore.getReconStatus(props.reconId))
const status = computed(() => reconStatus.value?.status || 'pending')
const errorMessage = computed(() => reconStatus.value?.error || '')

const tools = computed(() => [
  {
    name: 'nmap',
    label: 'Nmap Port Scan',
    status: getToolStatus('nmap'),
    output: getToolOutput('nmap')
  },
  {
    name: 'amass',
    label: 'Amass Subdomain Enum',
    status: getToolStatus('amass'),
    output: getToolOutput('amass')
  },
  {
    name: 'subfinder',
    label: 'Subfinder Subdomain Enum',
    status: getToolStatus('subfinder'),
    output: getToolOutput('subfinder')
  },
  {
    name: 'bbot',
    label: 'BBOT OSINT Scan',
    status: getToolStatus('bbot'),
    output: getToolOutput('bbot')
  }
])

const totalTools = computed(() => tools.value.length)
const completedTools = computed(() => 
  tools.value.filter(t => t.status === 'completed').length
)

const progressColor = computed(() => {
  if (status.value === 'error') return 'error'
  if (status.value === 'completed') return 'success'
  return 'primary'
})

// Methods
const getToolStatus = (toolName: string): string => {
  const progress = reconStatus.value?.progress || {}
  if (progress[toolName]) {
    return progress[toolName].status
  }
  
  // Check if tool has results
  const results = attackersStore.getReconResults(props.reconId)
  if (results?.tools?.[toolName]) {
    return results.tools[toolName].status || 'completed'
  }
  
  return 'pending'
}

const getToolOutput = (toolName: string): string => {
  const results = attackersStore.getReconResults(props.reconId)
  if (!results?.tools?.[toolName]) return ''
  
  const toolData = results.tools[toolName]
  
  // Format output based on tool
  if (toolName === 'nmap') {
    let output = ''
    
    // Check host discovery
    const hostDiscovery = toolData.host_discovery
    if (hostDiscovery) {
      if (hostDiscovery.error) {
        output += `❌ Host Discovery Error: ${hostDiscovery.error}\n\n`
      } else if (hostDiscovery.status === 'timeout') {
        output += `⏱️ Host Discovery: Timed out\n\n`
      } else {
        output += `🔍 Host Discovery: ${hostDiscovery.host_up ? '✅ Host is UP' : '❌ Host appears DOWN'}\n\n`
      }
    }
    
    // Check port scan
    const portScan = toolData.port_scan
    if (portScan) {
      if (portScan.error) {
        output += `❌ Port Scan Error: ${portScan.error}\n`
      } else if (portScan.status === 'timeout') {
        output += `⏱️ Port Scan: Timed out\n`
      } else if (portScan.open_ports && portScan.open_ports.length > 0) {
        const openPorts = portScan.open_ports.filter((p: any) => p.state === 'open')
        output += `🔓 Open Ports Found: ${openPorts.length}\n`
        output += '─'.repeat(40) + '\n'
        openPorts.forEach((p: any) => {
          output += `  ${p.port}/${p.protocol} - ${p.service || 'unknown'}\n`
        })
      } else {
        output += `🔒 No open ports found\n`
      }
    }
    
    return output || 'No nmap results available'
    
  } else if (toolName === 'amass') {
    if (toolData.error) {
      return `❌ Error: ${toolData.error}`
    }
    if (toolData.status === 'timeout') {
      return `⏱️ Timed out after scanning`
    }
    const subdomains = toolData.subdomains || []
    if (subdomains.length === 0) {
      return '🔍 No subdomains found'
    }
    let output = `🌐 AMASS Subdomains Found: ${subdomains.length}\n`
    output += '─'.repeat(40) + '\n'
    subdomains.forEach((s: string) => {
      output += `  • ${s}\n`
    })
    return output
    
  } else if (toolName === 'subfinder') {
    if (toolData.error) {
      return `❌ Error: ${toolData.error}`
    }
    if (toolData.status === 'timeout') {
      return `⏱️ Timed out after scanning`
    }
    const subdomains = toolData.subdomains || []
    if (subdomains.length === 0) {
      return '🔍 No subdomains found'
    }
    let output = `🔎 SUBFINDER Subdomains Found: ${subdomains.length}\n`
    output += '─'.repeat(40) + '\n'
    subdomains.forEach((s: string) => {
      output += `  • ${s}\n`
    })
    return output
    
  } else if (toolName === 'bbot') {
    if (toolData.error) {
      return `❌ Error: ${toolData.error}`
    }
    if (toolData.status === 'timeout') {
      return `⏱️ BBOT timed out (this is common for large scans)`
    }
    
    let output = '🤖 BBOT OSINT Results\n'
    output += '─'.repeat(40) + '\n'
    
    // Show subdomains if found
    if (toolData.subdomains && toolData.subdomains.length > 0) {
      output += `\n🌐 Subdomains (${toolData.subdomains.length}):\n`
      toolData.subdomains.forEach((s: string) => {
        output += `  • ${s}\n`
      })
    }
    
    // Show emails if found
    if (toolData.emails && toolData.emails.length > 0) {
      output += `\n📧 Emails (${toolData.emails.length}):\n`
      toolData.emails.forEach((e: string) => {
        output += `  • ${e}\n`
      })
    }
    
    // Show technologies if found
    if (toolData.technologies && toolData.technologies.length > 0) {
      output += `\n🛠️ Technologies (${toolData.technologies.length}):\n`
      toolData.technologies.forEach((t: string) => {
        output += `  • ${t}\n`
      })
    }
    
    if (output === '🤖 BBOT OSINT Results\n' + '─'.repeat(40) + '\n') {
      return '🔍 No BBOT findings'
    }
    
    return output
  }
  
  // Default: show raw JSON
  return JSON.stringify(toolData, null, 2)
}

const getToolIcon = (status: string): string => {
  switch (status) {
    case 'completed': return 'mdi-check-circle'
    case 'running': return 'mdi-loading mdi-spin'
    case 'error': return 'mdi-alert-circle'
    case 'timeout': return 'mdi-clock-alert'
    default: return 'mdi-circle-outline'
  }
}

const getToolIconColor = (status: string): string => {
  switch (status) {
    case 'completed': return 'success'
    case 'running': return 'primary'
    case 'error': return 'error'
    case 'timeout': return 'warning'
    default: return 'grey'
  }
}

const getToolChipColor = (status: string): string => {
  switch (status) {
    case 'completed': return 'success'
    case 'running': return 'info'
    case 'error': return 'error'
    case 'timeout': return 'warning'
    default: return 'default'
  }
}

const toggleOutput = (toolName: string) => {
  showOutput.value = showOutput.value === toolName ? '' : toolName
}

const downloadReport = async (format: 'docx' | 'pdf') => {
  if (format === 'docx') {
    downloadingDocx.value = true
  } else {
    downloadingPdf.value = true
  }
  
  try {
    await attackersStore.downloadReport(props.reconId, format)
  } catch (error) {
    console.error('Failed to download report:', error)
    alert(`Failed to download ${format.toUpperCase()} report`)
  } finally {
    if (format === 'docx') {
      downloadingDocx.value = false
    } else {
      downloadingPdf.value = false
    }
  }
}

const close = () => {
  if (pollInterval.value) {
    clearInterval(pollInterval.value)
  }
  emit('close')
}

const startPolling = () => {
  // Poll status every 3 seconds
  pollInterval.value = setInterval(async () => {
    await attackersStore.pollReconStatus(props.reconId)
    
    // Stop polling if completed or error
    if (status.value === 'completed' || status.value === 'error') {
      clearInterval(pollInterval.value)
      pollInterval.value = null
    }
  }, 3000)
}

// Watchers
watch(() => props.reconId, (newId) => {
  if (newId) {
    startPolling()
  }
}, { immediate: true })

// Cleanup
onUnmounted(() => {
  if (pollInterval.value) {
    clearInterval(pollInterval.value)
  }
})
</script>

<style scoped>
.border-t {
  border-top: 1px solid rgba(var(--v-border-color), var(--v-border-opacity));
}

.tool-timeline {
  max-height: 400px;
  overflow-y: auto;
}

.output-terminal {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 12px;
  border-radius: 4px;
  font-family: 'Courier New', monospace;
  font-size: 12px;
  overflow-x: auto;
  max-height: 200px;
  overflow-y: auto;
}

.gap-3 {
  gap: 12px;
}
</style>
