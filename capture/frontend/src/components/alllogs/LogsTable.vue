<template>
  <v-card class="logs-table-card" elevation="2" rounded="lg">
    <v-card-title class="d-flex align-center pa-4">
      <v-icon icon="mdi-file-document-multiple" class="mr-2" size="24" />
      <span class="text-h6 font-weight-medium">Logs</span>
      <v-spacer />
      <v-chip
        v-if="loading"
        color="primary"
        size="small"
        variant="flat"
        class="mr-2"
      >
        <v-icon start size="small" class="rotating">mdi-refresh</v-icon>
        <span class="text-caption">Updating...</span>
      </v-chip>
      <v-chip
        v-else-if="logs.length > 0"
        color="success"
        size="small"
        variant="flat"
      >
        {{ logs.length }} logs
      </v-chip>
    </v-card-title>

    <v-data-table
      :headers="headers"
      :items="logs"
      :loading="loading"
      class="elevation-0"
      :items-per-page="25"
      :items-per-page-options="[10, 25, 50, 100]"
      @click:row="onRowClick"
      :no-data-text="loading ? 'Loading logs...' : 'No logs found'"
      hover
    >
      <template v-slot:item.timestamp="{ item }">
        <div class="d-flex flex-column">
          <span class="text-body-2 font-weight-medium">{{ formatDate(item.timestamp) }}</span>
          <span class="text-caption text-medium-emphasis">{{ formatTime(item.timestamp) }}</span>
        </div>
      </template>

      <template v-slot:item.src_ip="{ item }">
        <div class="d-flex align-center">
          <v-icon icon="mdi-ip-network" size="16" class="mr-1" />
          <span class="font-weight-medium">{{ item.src_ip }}</span>
        </div>
      </template>

      <template v-slot:item.type="{ item }">
        <v-chip
          :color="getTypeColor(item.type)"
          size="small"
          variant="flat"
        >
          <v-icon start :icon="getTypeIcon(item.type)" size="16" />
          {{ item.type }}
        </v-chip>
      </template>

      <template v-slot:item.attack_tool="{ item }">
        <span v-if="item.attack_tool && item.attack_tool !== 'unknown'" class="font-weight-bold text-error">
          <v-icon icon="mdi-shield-alert" size="16" class="mr-1" />
          {{ item.attack_tool }}
        </span>
        <span v-else class="text-medium-emphasis">-</span>
      </template>

      <template v-slot:item.geoip="{ item }">
        <div v-if="item.geoip" class="d-flex flex-column">
          <span class="text-body-2">
            <v-icon icon="mdi-map-marker" size="14" class="mr-1" />
            {{ item.geoip.country }}
          </span>
          <span class="text-caption text-medium-emphasis">{{ item.geoip.city }}</span>
        </div>
        <span v-else class="text-medium-emphasis">-</span>
      </template>

      <template v-slot:item.threat_level="{ item }">
        <v-chip
          v-if="item.threat_level"
          :color="getThreatColor(item.threat_level)"
          size="small"
          variant="flat"
        >
          <v-icon start :icon="getThreatIcon(item.threat_level)" size="14" />
          {{ item.threat_level }}
        </v-chip>
        <span v-else class="text-medium-emphasis">-</span>
      </template>

      <template v-slot:item.actions="{ item }">
        <v-btn
          icon="mdi-eye"
          variant="text"
          size="small"
          @click.stop="onRowClick(null, { item })"
        />
      </template>
    </v-data-table>

    <!-- Log Details Dialog -->
    <v-dialog v-model="dialog" max-width="800px">
      <v-card v-if="selectedLog">
        <v-card-title class="d-flex align-center">
          <v-icon icon="mdi-information" class="mr-2" />
          Log Details
          <v-spacer />
          <v-btn icon="mdi-close" variant="text" @click="dialog = false" />
        </v-card-title>
        <v-divider />
        <v-card-text class="pa-4">
          <v-row dense>
            <v-col cols="12" md="6">
              <v-list-item-title class="text-caption text-medium-emphasis">Timestamp</v-list-item-title>
              <v-list-item-subtitle>{{ formatDate(selectedLog.timestamp) }}</v-list-item-subtitle>
            </v-col>
            <v-col cols="12" md="6">
              <v-list-item-title class="text-caption text-medium-emphasis">Type</v-list-item-title>
              <v-list-item-subtitle>{{ selectedLog.type }}</v-list-item-subtitle>
            </v-col>
            <v-col cols="12" md="6">
              <v-list-item-title class="text-caption text-medium-emphasis">Source IP</v-list-item-title>
              <v-list-item-subtitle>{{ selectedLog.src_ip }}</v-list-item-subtitle>
            </v-col>
            <v-col cols="12" md="6" v-if="selectedLog.dst_ip">
              <v-list-item-title class="text-caption text-medium-emphasis">Destination IP</v-list-item-title>
              <v-list-item-subtitle>{{ selectedLog.dst_ip }}</v-list-item-subtitle>
            </v-col>
            <v-col cols="12" v-if="selectedLog.attack_tool">
              <v-list-item-title class="text-caption text-medium-emphasis">Attack Tool</v-list-item-title>
              <v-list-item-subtitle class="text-error font-weight-bold">{{ selectedLog.attack_tool }}</v-list-item-subtitle>
            </v-col>
            <v-col cols="12" v-if="selectedLog.threat_level">
              <v-list-item-title class="text-caption text-medium-emphasis">Threat Level</v-list-item-title>
              <v-chip :color="getThreatColor(selectedLog.threat_level)" size="small" class="mt-1">
                {{ selectedLog.threat_level }} (Score: {{ selectedLog.threat_score || 0 }}/100)
              </v-chip>
            </v-col>
            <v-col cols="12" v-if="selectedLog.attack_techniques">
              <v-list-item-title class="text-caption text-medium-emphasis">Attack Techniques</v-list-item-title>
              <div class="d-flex flex-wrap ga-1 mt-1">
                <v-chip v-for="technique in selectedLog.attack_techniques" :key="technique" size="x-small" color="error" variant="outlined">
                  {{ technique }}
                </v-chip>
              </div>
            </v-col>
            <v-col cols="12" v-if="selectedLog.geoip">
              <v-list-item-title class="text-caption text-medium-emphasis">GeoIP Information</v-list-item-title>
              <v-list-item-subtitle>
                <div><v-icon size="14" class="mr-1">mdi-earth</v-icon>{{ selectedLog.geoip.country }}, {{ selectedLog.geoip.city }}</div>
                <div v-if="selectedLog.geoip.isp" class="text-caption"><v-icon size="14" class="mr-1">mdi-server-network</v-icon>{{ selectedLog.geoip.isp }}</div>
              </v-list-item-subtitle>
            </v-col>
            <v-col cols="12" v-if="selectedLog.osint && Object.keys(selectedLog.osint).length > 0">
              <v-list-item-title class="text-caption text-medium-emphasis">Threat Intelligence (OSINT)</v-list-item-title>
              <v-card variant="outlined" class="mt-1 pa-2">
                <div v-if="selectedLog.osint.abuseipdb" class="text-caption">
                  <strong>AbuseIPDB:</strong> {{ selectedLog.osint.abuseipdb.abuseConfidenceScore }}% abuse score
                </div>
                <div v-if="selectedLog.osint.shodan" class="text-caption">
                  <strong>Shodan:</strong> {{ selectedLog.osint.shodan.ports?.length || 0 }} open ports
                </div>
                <div v-if="selectedLog.osint.virustotal" class="text-caption">
                  <strong>VirusTotal:</strong> {{ selectedLog.osint.virustotal.malicious || 0 }} malicious detections
                </div>
              </v-card>
            </v-col>
            <v-col cols="12" v-if="selectedLog.message">
              <v-list-item-title class="text-caption text-medium-emphasis">Message</v-list-item-title>
              <v-list-item-subtitle>{{ selectedLog.message }}</v-list-item-subtitle>
            </v-col>
          </v-row>
        </v-card-text>
      </v-card>
    </v-dialog>
  </v-card>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import type { Log } from '@/stores/dashboard'
import type { ExtendedLog } from '@/types/logs'

interface Props {
  logs: Log[]
  loading: boolean
}

const props = defineProps<Props>()

const dialog = ref(false)
const selectedLog = ref<ExtendedLog | null>(null)

const headers = [
  { title: 'Timestamp', key: 'timestamp', sortable: true, width: '180px' },
  { title: 'Source IP', key: 'src_ip', sortable: true, width: '150px' },
  { title: 'Threat', key: 'threat_level', sortable: true, width: '120px' },
  { title: 'Tool', key: 'attack_tool', sortable: true, width: '140px' },
  { title: 'Location', key: 'geoip', sortable: false, width: '180px' },
  { title: 'Actions', key: 'actions', sortable: false, width: '80px' }
]

function formatDate(timestamp: string) {
  return new Date(timestamp).toLocaleDateString('vi-VN', {
    timeZone: 'Asia/Ho_Chi_Minh',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  })
}

function formatTime(timestamp: string) {
  return new Date(timestamp).toLocaleTimeString('vi-VN', {
    timeZone: 'Asia/Ho_Chi_Minh',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
}

function getTypeColor(type: string): string {
  const colors: Record<string, string> = {
    attack: 'error',
    honeypot: 'warning',
    traffic: 'info',
    error: 'error'
  }
  return colors[type] || 'default'
}


function getTypeIcon(type: string): string {
  const icons: Record<string, string> = {
    attack: 'mdi-shield-alert',
    honeypot: 'mdi-bee',
    traffic: 'mdi-traffic-light',
    error: 'mdi-alert-circle'
  }
  return icons[type] || 'mdi-information'
}

function getThreatColor(level: string): string {
  const colors: Record<string, string> = {
    critical: 'error',
    high: 'warning',
    medium: 'info',
    low: 'success'
  }
  return colors[level] || 'default'
}

function getThreatIcon(level: string): string {
  const icons: Record<string, string> = {
    critical: 'mdi-alert-octagon',
    high: 'mdi-alert',
    medium: 'mdi-alert-circle-outline',
    low: 'mdi-information-outline'
  }
  return icons[level] || 'mdi-shield'
}

function onRowClick(event: unknown, { item }: { item: Log | ExtendedLog }) {
  selectedLog.value = item as ExtendedLog
  dialog.value = true
}
</script>

<style scoped>
.logs-table-card {
  border-radius: 12px;
  overflow: hidden;
}

:deep(.v-data-table) {
  border-radius: 0 0 12px 12px;
}

:deep(.v-data-table__tr) {
  cursor: pointer;
  transition: background-color 0.2s;
}

:deep(.v-data-table__tr:hover) {
  background-color: rgba(var(--v-theme-primary), 0.05);
}

.rotating {
  animation: rotate 1s linear infinite;
}

@keyframes rotate {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}
</style>

