<template>
  <v-card class="logs-table-card" elevation="2">
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
      class="elevation-1"
      items-per-page="25"
      @click:row="onRowClick"
      :no-data-text="loading ? 'Loading logs...' : 'No logs found'"
    >
      <template v-slot:item.timestamp="{ item }">
        {{ formatDate(item.timestamp) }}
      </template>

      <template v-slot:item.type="{ item }">
        <v-chip
          :color="getTypeColor(item.type)"
          size="small"
        >
          {{ item.type }}
        </v-chip>
      </template>

      <template v-slot:item.attack_tool="{ item }">
        <span v-if="item.attack_tool" class="font-weight-bold">
          {{ item.attack_tool }}
        </span>
        <span v-else class="text-grey">-</span>
      </template>

      <template v-slot:item.geoip="{ item }">
        <div v-if="item.geoip" class="d-flex flex-column">
          <span class="font-weight-bold">{{ item.geoip.country }}</span>
          <span class="text-caption">{{ item.geoip.city }}</span>
          <span class="text-caption text-grey">{{ item.geoip.isp }}</span>
        </div>
        <span v-else class="text-grey">-</span>
      </template>

      <template v-slot:item.method="{ item }">
        <v-chip
          :color="getMethodColor(item.method)"
          size="small"
          variant="outlined"
        >
          {{ item.method || 'N/A' }}
        </v-chip>
      </template>

      <template v-slot:item.path="{ item }">
        <code class="text-caption">{{ item.path || item.message || '-' }}</code>
      </template>

      <template v-slot:item.user_agent="{ item }">
        <span class="text-caption" :title="item.user_agent">
          {{ truncateText(item.user_agent, 30) }}
        </span>
      </template>
    </v-data-table>
    <!-- Details Dialog -->
    <v-dialog v-model="detailsOpen" max-width="900">
      <v-card>
        <v-card-title class="d-flex align-center">
          <v-icon icon="mdi-information-outline" class="mr-2" />
          Log Details
          <v-spacer />
          <v-btn icon="mdi-close" variant="text" @click="detailsOpen = false" />
        </v-card-title>
        <v-card-text>
          <v-row>
            <v-col cols="12" md="6">
              <v-list density="compact">
                <v-list-item title="Timestamp" :subtitle="formatDate(selectedLog?.timestamp || '')" />
                <v-list-item title="Type" :subtitle="selectedLog?.type || '-'" />
                <v-list-item title="Source IP" :subtitle="selectedLog?.src_ip || '-'" />
                <v-list-item title="Method" :subtitle="selectedLog?.method || '-'" />
                <v-list-item title="Path" :subtitle="selectedLog?.path || '-'" />
                <v-list-item title="User Agent" :subtitle="selectedLog?.user_agent || '-'" />
                <v-list-item title="Attack Tool" :subtitle="selectedLog?.attack_tool || '-'" />
              </v-list>
            </v-col>
            <v-col cols="12" md="6">
              <v-card variant="outlined">
                <v-card-title class="text-subtitle-2">GeoIP</v-card-title>
                <v-card-text>
                  <div v-if="selectedLog?.geoip">
                    <div><strong>Country:</strong> {{ selectedLog?.geoip?.country }}</div>
                    <div><strong>City:</strong> {{ selectedLog?.geoip?.city }}</div>
                    <div><strong>ISP:</strong> {{ selectedLog?.geoip?.isp || '-' }}</div>
                  </div>
                  <div v-else>-</div>
                </v-card-text>
              </v-card>
            </v-col>
            <v-col cols="12">
              <v-card variant="outlined">
                <v-card-title class="text-subtitle-2">Raw JSON</v-card-title>
                <v-card-text>
                  <pre class="code-block">{{ prettyJson(selectedLog) }}</pre>
                </v-card-text>
              </v-card>
            </v-col>
          </v-row>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn color="primary" @click="detailsOpen = false">Close</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-card>
</template>

<script setup lang="ts">

interface Log {
  timestamp: string
  type: string
  src_ip: string
  attack_tool?: string
  geoip?: {
    country: string
    city: string
    isp?: string
  }
  message?: string
  method?: string
  path?: string
  user_agent?: string
}

interface Props {
  logs: Log[]
  loading: boolean
}

const props = defineProps<Props>()

defineEmits<{
  refresh: []
}>()

const headers = [
  { title: 'Timestamp', key: 'timestamp', sortable: true, width: '180px' },
  { title: 'Type', key: 'type', sortable: true, width: '100px' },
  { title: 'Source IP', key: 'src_ip', sortable: true, width: '120px' },
  { title: 'Attack Tool', key: 'attack_tool', sortable: false, width: '120px' },
  { title: 'Location', key: 'geoip', sortable: false, width: '150px' },
  { title: 'Method', key: 'method', sortable: false, width: '80px' },
  { title: 'Path', key: 'path', sortable: false, width: '200px' },
  { title: 'User Agent', key: 'user_agent', sortable: false, width: '250px' }
]

function formatDate(timestamp: string) {
  return new Date(timestamp).toLocaleString('vi-VN', {
    timeZone: 'Asia/Ho_Chi_Minh',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
}

function getTypeColor(type: string) {
  switch (type) {
    case 'attack': return 'error'
    case 'honeypot': return 'warning'
    case 'traffic': return 'info'
    default: return 'grey'
  }
}

function getMethodColor(method: string) {
  switch (method?.toUpperCase()) {
    case 'GET': return 'success'
    case 'POST': return 'primary'
    case 'PUT': return 'warning'
    case 'DELETE': return 'error'
    case 'PATCH': return 'info'
    default: return 'grey'
  }
}

function truncateText(text: string, maxLength: number) {
  if (!text) return '-'
  return text.length > maxLength ? text.substring(0, maxLength) + '...' : text
}

// Details modal state
import { ref } from 'vue'
const detailsOpen = ref(false)
const selectedLog = ref<Log | null>(null)

function onRowClick(event: MouseEvent, { item }: any) {
  // Vuetify passes { item } containing the raw object
  selectedLog.value = item as Log
  detailsOpen.value = true
}

function prettyJson(obj: unknown) {
  try { return JSON.stringify(obj, null, 2) } catch { return '-' }
}
</script>

<style scoped>
.logs-table-card {
  border-radius: 12px;
  overflow: hidden;
}

.code-block {
  white-space: pre-wrap;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  font-size: 12px;
  background-color: rgba(var(--v-theme-surface), 0.8);
  padding: 12px;
  border-radius: 8px;
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

:deep(.v-data-table) {
  border-radius: 0 0 12px 12px;
}

:deep(.v-data-table__thead) {
  background-color: rgba(var(--v-theme-surface), 0.5);
}
</style>
