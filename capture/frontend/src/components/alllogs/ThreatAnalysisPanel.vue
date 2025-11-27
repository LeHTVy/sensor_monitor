<template>
  <div v-if="log" class="threat-analysis pa-6">
    <div class="d-flex align-center justify-space-between mb-6">
      <h2 class="text-h5">THREAT ANALYSIS REPORT</h2>
      <v-btn variant="text" icon size="small">
        <v-icon>mdi-refresh</v-icon>
      </v-btn>
    </div>
    
    <!-- GeoIP Map Placeholder -->
    <v-card class="mb-4" elevation="2">
      <v-card-title class="text-subtitle-1">
        <v-icon start color="primary">mdi-earth</v-icon>
        Location & Network Info
      </v-card-title>
      <v-card-text>
        <div class="map-placeholder d-flex align-center justify-center">
          <div class="text-center">
            <v-icon size="64" color="primary">mdi-map-marker</v-icon>
            <p class="text-h6 mt-4">{{ log.geoip?.country || 'Unknown Location' }}</p>
            <p class="text-caption text-medium-emphasis">
              {{ log.geoip?.city || '' }}
              {{ log.geoip?.lat && log.geoip?.lon ? `(${log.geoip.lat}, ${log.geoip.lon})` : '' }}
            </p>
            
            <!-- ISP Information -->
            <div v-if="log.geoip?.isp || log.geoip?.org" class="mt-4">
              <v-divider class="my-3" />
              <div v-if="log.geoip?.isp" class="d-flex align-center justify-center mb-2">
                <v-icon size="small" class="mr-2">mdi-domain</v-icon>
                <span class="text-body-2"><strong>ISP:</strong> {{ log.geoip.isp }}</span>
              </div>
              <div v-if="log.geoip?.org && log.geoip.org !== log.geoip.isp" class="d-flex align-center justify-center">
                <v-icon size="small" class="mr-2">mdi-office-building</v-icon>
                <span class="text-body-2"><strong>Org:</strong> {{ log.geoip.org }}</span>
              </div>
            </div>
          </div>
        </div>
      </v-card-text>
    </v-card>
    
    <!-- MITRE ATT&CK -->
    <v-card class="mb-4" elevation="2">
      <v-card-title class="text-subtitle-1">
        <v-icon start color="error">mdi-shield-alert</v-icon>
        MITRE ATTACK
      </v-card-title>
      <v-card-text>
        <div v-if="log.attack_techniques && log.attack_techniques.length > 0">
          <v-chip
            v-for="technique in log.attack_techniques"
            :key="technique"
            color="error"
            variant="outlined"
            class="mr-2 mb-2"
            size="small"
          >
            {{ technique }}
          </v-chip>
        </div>
        <div v-else class="text-caption text-medium-emphasis">
          No MITRE techniques detected
        </div>
      </v-card-text>
    </v-card>
    
    <!-- Reputation Score -->
    <v-card class="mb-4" elevation="2">
      <v-card-title class="text-subtitle-1">
        <v-icon start color="warning">mdi-chart-bar</v-icon>
        Reputation Score
      </v-card-title>
      <v-card-text>
        <v-progress-linear
          :model-value="log.threat_score || 0"
          :color="getScoreColor(log.threat_score)"
          height="20"
          class="mb-2"
        >
          <template v-slot:default>
            <strong>{{ log.threat_score || 0 }}/100</strong>
          </template>
        </v-progress-linear>
        
        <!-- Debug info -->
        <div v-if="!log.threat_score && !log.osint" class="text-caption text-medium-emphasis mt-2">
          <v-icon size="small" class="mr-1">mdi-information-outline</v-icon>
          OSINT enrichment data not available for this log
        </div>
        
        <!-- OSINT Data -->
        <div v-if="log.osint" class="mt-4">
          <h4 class="text-subtitle-2 mb-2">OSINT Intelligence:</h4>
          
          <div v-if="log.osint.abuseipdb" class="mb-2">
            <v-chip size="small" variant="outlined" class="mr-2">AbuseIPDB</v-chip>
            <span class="text-caption">Reports: {{ log.osint.abuseipdb.abuse_confidence_score || log.osint.abuseipdb.abuseConfidenceScore }}%</span>
          </div>
          
          <div v-if="log.osint.shodan" class="mb-2">
            <v-chip size="small" variant="outlined" class="mr-2">Shodan</v-chip>
            <span class="text-caption">
              {{ log.osint.shodan.org || log.osint.shodan.isp || 'Unknown Org' }}
            </span>
          </div>
          
          <div v-if="log.osint.virustotal">
            <v-chip size="small" variant="outlined" class="mr-2">VirusTotal</v-chip>
            <span class="text-caption">Malicious: {{ log.osint.virustotal.malicious || 0 }}</span>
          </div>
          
          <!-- Show if OSINT object exists but has no data -->
          <div v-if="!log.osint.abuseipdb && !log.osint.shodan && !log.osint.virustotal" class="text-caption text-medium-emphasis">
            <v-icon size="small" class="mr-1">mdi-information-outline</v-icon>
            OSINT data collected but no threat intelligence found
          </div>
        </div>
        
        <!-- Add console log to debug -->
        <div v-if="false">
          Debug: {{ JSON.stringify({ hasOsint: !!log.osint, hasThreatScore: !!log.threat_score }) }}
        </div>
      </v-card-text>
    </v-card>
    
    <!-- Raw Payload -->
    <v-card class="mb-4" elevation="2">
      <v-card-title class="text-subtitle-1">
        <v-icon start>mdi-code-json</v-icon>
        Raw Payload
      </v-card-title>
      <v-card-text>
        <div class="code-block">
          <pre>{{ formatPayload(log) }}</pre>
        </div>
      </v-card-text>
    </v-card>
    
    <!-- LLM Analysis -->
    <v-card v-if="llmAnalysis" elevation="2">
      <v-card-title class="text-subtitle-1">
        <v-icon start color="info">mdi-robot</v-icon>
        AI Analysis
      </v-card-title>
      <v-card-text>
        <div class="mb-3">
          <strong>Intent:</strong>
          <p class="text-body-2">{{ llmAnalysis.intent }}</p>
        </div>
        
        <div>
          <strong>Recommendations:</strong>
          <ul class="mt-2">
            <li v-for="(rec, index) in llmAnalysis.recommendations" :key="index" class="text-body-2">
              {{ rec }}
            </li>
          </ul>
        </div>
      </v-card-text>
    </v-card>
    

  </div>
  
  <div v-else class="pa-6 text-center text-medium-emphasis">
    <v-icon size="64" class="mb-4">mdi-file-document-outline</v-icon>
    <p class="text-h6">Select a threat capsule to view details</p>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import type { Log } from '@/stores/dashboard'

const props = defineProps<{ log: Log | null }>()
const llmAnalysis = ref<Log['llm_analysis']>(null)

watch(() => props.log, async (newLog) => {
  if (newLog) {
    // Debug: Log the structure to console
    console.log('🔍 ThreatAnalysisPanel - Log data:', {
      hasOsint: !!newLog.osint,
      hasThreatScore: !!newLog.threat_score,
      osintKeys: newLog.osint ? Object.keys(newLog.osint) : [],
      threatScore: newLog.threat_score,
      logKeys: Object.keys(newLog).filter(k => k.includes('threat') || k.includes('osint'))
    })

    // Check if LLM analysis exists in the log
    if (newLog.llm_analysis) {
      llmAnalysis.value = newLog.llm_analysis
    } else {
      llmAnalysis.value = null
    }
  }
})

function getScoreColor(score?: number) {
  if (!score) return 'grey'
  if (score >= 75) return 'error'
  if (score >= 50) return 'warning'
  if (score >= 25) return 'info'
  return 'success'
}

function formatPayload(log: Log) {
  // Check if this is a network log (has protocol/flags)
  if (log.protocol || log.flags !== undefined) {
    return JSON.stringify({
      protocol: log.protocol,
      src_port: log.src_port,
      dst_port: log.dst_port,
      flags: log.flags,
      size: log.size,
      payload: log.payload,
      type: log.type
    }, null, 2)
  }
  
  // Default to HTTP log
  return JSON.stringify({
    method: log.method,
    path: log.path,
    headers: log.headers,
    body: log.body,
    user_agent: log.user_agent,
  }, null, 2)
}
</script>

<style scoped>
.map-placeholder {
  min-height: 200px;
  background: rgba(var(--v-theme-surface-variant), 0.5);
  border-radius: 8px;
}

.code-block {
  background: rgba(var(--v-theme-surface-variant), 0.5);
  border-radius: 4px;
  padding: 12px;
  overflow-x: auto;
  max-height: 300px;
}

.code-block pre {
  margin: 0;
  font-family: 'Courier New', monospace;
  font-size: 12px;
}
</style>
