<template>
  <v-card>
    <v-card-title>
      <v-icon icon="mdi-file-document-multiple" class="mr-2" />
      Logs
      <v-spacer />
      <v-btn
        @click="$emit('refresh')"
        :loading="loading"
        color="primary"
        variant="outlined"
      >
        <v-icon left>mdi-refresh</v-icon>
        Refresh
      </v-btn>
    </v-card-title>

    <v-data-table
      :headers="headers"
      :items="logs"
      :loading="loading"
      class="elevation-1"
      items-per-page="25"
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

defineProps<Props>()

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
</script>
