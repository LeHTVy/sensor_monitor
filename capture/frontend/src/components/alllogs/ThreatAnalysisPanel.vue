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

    <!-- Attack Tool Detection -->
    <v-card class="mb-4" elevation="2">
      <v-card-title class="text-subtitle-1">
        <v-icon start color="error">mdi-tools</v-icon>
        Attack Tool Detection
      </v-card-title>
      <v-card-text>
        <!-- Primary Tool -->
        <div v-if="log.attack_tool && log.attack_tool !== 'unknown'" class="mb-3">
          <v-chip
            color="error"
            variant="flat"
            size="large"
            prepend-icon="mdi-alert-circle"
            class="mb-2"
          >
            {{ log.attack_tool.toUpperCase() }}
          </v-chip>
          
          <!-- Tool Info -->
          <div v-if="log.attack_tool_info" class="mt-3 ml-2">
            <div v-if="log.attack_tool_info.version" class="text-caption mb-1">
              <v-icon size="small" class="mr-1">mdi-tag</v-icon>
              <strong>Version:</strong> {{ log.attack_tool_info.version }}
            </div>
            <div v-if="log.attack_tool_info.capabilities && Array.isArray(log.attack_tool_info.capabilities)" class="text-caption mb-1">
              <v-icon size="small" class="mr-1">mdi-feature-search</v-icon>
              <strong>Capabilities:</strong> {{ log.attack_tool_info.capabilities.join(', ') }}
            </div>
            <div v-if="log.attack_tool_info.description" class="text-caption mt-2 pa-2" style="background: rgba(var(--v-theme-surface-variant), 0.5); border-radius: 4px;">
              {{ log.attack_tool_info.description }}
            </div>
          </div>
        </div>

        <!-- Attack Techniques (if available) -->
        <div v-if="log.attack_technique && log.attack_technique.length > 0" class="mt-3">
          <div class="text-caption font-weight-bold mb-2">Techniques Used:</div>
          <v-chip
            v-for="technique in log.attack_technique"
            :key="technique"
            color="warning"
            variant="outlined"
            class="mr-2 mb-2"
            size="small"
          >
            {{ technique }}
          </v-chip>
        </div>

        <!-- User Agent Pattern (for web attacks) -->
        <div v-if="log.user_agent && !log.attack_tool" class="mt-3">
          <div class="text-caption font-weight-bold mb-2">User Agent Pattern:</div>
          <div class="text-caption pa-2" style="background: rgba(var(--v-theme-surface-variant), 0.5); border-radius: 4px; font-family: monospace;">
            {{ log.user_agent }}
          </div>
        </div>

        <!-- No tool detected -->
        <div v-if="!log.attack_tool || log.attack_tool === 'unknown'" class="text-caption text-medium-emphasis">
          <v-icon size="small" class="mr-1">mdi-information-outline</v-icon>
          No specific attack tool detected - may be manual reconnaissance or unknown tool
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

    <!-- File Analysis (for file uploads) -->
    <v-card v-if="isFileUpload(log)" class="mb-4" elevation="2">
      <v-card-title class="text-subtitle-1">
        <v-icon start>mdi-file-search</v-icon>
        File Analysis
        <v-chip v-if="log.risk_level" :color="getRiskColor(log.risk_level)" size="small" class="ml-2">
          {{ log.risk_level }}
        </v-chip>
      </v-card-title>
      <v-card-text>
        <!-- Basic File Info -->
        <div class="mb-3">
          <div class="text-caption text-medium-emphasis">Filename</div>
          <div class="font-weight-medium">{{ log.original_filename || log.filename || 'Unknown' }}</div>
        </div>
        
        <div v-if="log.file_size" class="mb-3">
          <div class="text-caption text-medium-emphasis">File Size</div>
          <div>{{ formatFileSize(log.file_size) }}</div>
        </div>

        <!-- File Type -->
        <div v-if="log.file_type" class="mb-3">
          <div class="text-caption text-medium-emphasis">File Type</div>
          <div>{{ log.file_type.magic || log.file_type.mime || 'Unknown' }}</div>
          <v-chip v-if="log.file_type.extension_mismatch" color="warning" size="x-small" class="mt-1">
            Extension Mismatch
          </v-chip>
        </div>

        <!-- Risk Score -->
        <div v-if="log.risk_score !== undefined" class="mb-3">
          <div class="text-caption text-medium-emphasis">Risk Score</div>
          <v-progress-linear
            :model-value="log.risk_score"
            :color="getRiskColor(log.risk_level)"
            height="20"
            class="mb-1"
          >
            <strong>{{ log.risk_score }}/100</strong>
          </v-progress-linear>
        </div>

        <!-- Hashes -->
        <div v-if="log.hashes" class="mb-3">
          <div class="text-caption text-medium-emphasis">File Hashes</div>
          <div class="code-block text-caption" style="font-family: monospace; word-break: break-all;">
            <div v-if="log.hashes.md5"><strong>MD5:</strong> {{ log.hashes.md5 }}</div>
            <div v-if="log.hashes.sha256"><strong>SHA256:</strong> {{ log.hashes.sha256 }}</div>
          </div>
        </div>

        <!-- Suspicious Patterns -->
        <div v-if="hasSuspiciousPatterns(log)" class="mb-3">
          <div class="text-caption text-medium-emphasis">Suspicious Patterns</div>
          <div v-for="(values, key) in getSuspiciousPatterns(log)" :key="key" class="mt-1">
            <v-chip color="error" size="x-small" class="mr-1">{{ key }}</v-chip>
            <span class="text-caption">{{ values.slice(0, 3).join(', ') }}</span>
          </div>
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

  return JSON.stringify({
    method: log.method,
    path: log.path,
    args: log.args,
    form_data: log.form_data,
    json_body: log.json_body,
    raw_body: log.raw_body,
    headers: log.headers,
    user_agent: log.user_agent,
  }, null, 2)
}

// File Analysis Helpers
function isFileUpload(log: Log): boolean {
  const logAny = log as any
  return logAny.type === 'file_upload' || 
         logAny.event_type === 'file_upload' ||
         (log.path === '/upload' && log.method === 'POST') ||
         !!logAny.original_filename ||
         !!logAny.hashes
}

function getRiskColor(riskLevel?: string): string {
  if (!riskLevel) return 'grey'
  switch (riskLevel.toUpperCase()) {
    case 'CRITICAL': return 'error'
    case 'HIGH': return 'deep-orange'
    case 'MEDIUM': return 'warning'
    case 'LOW': return 'info'
    case 'CLEAN': return 'success'
    default: return 'grey'
  }
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

function hasSuspiciousPatterns(log: Log): boolean {
  const logAny = log as any
  const patterns = logAny.static_analysis?.suspicious_patterns || logAny.suspicious_patterns
  return patterns && Object.keys(patterns).length > 0
}

function getSuspiciousPatterns(log: Log): Record<string, string[]> {
  const logAny = log as any
  return logAny.static_analysis?.suspicious_patterns || logAny.suspicious_patterns || {}
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
