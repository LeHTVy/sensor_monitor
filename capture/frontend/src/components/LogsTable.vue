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
      <template #item.timestamp="{ item }">
        {{ formatDate(item.timestamp) }}
      </template>

      <template #item.type="{ item }">
        <v-chip
          :color="getTypeColor(item.type)"
          size="small"
        >
          {{ item.type }}
        </v-chip>
      </template>

      <template #item.attack_tool="{ item }">
        <span v-if="item.attack_tool" class="font-weight-bold">
          {{ item.attack_tool }}
        </span>
        <span v-else class="text-grey">-</span>
      </template>

      <template #item.geoip="{ item }">
        <span v-if="item.geoip">
          {{ item.geoip.country }}, {{ item.geoip.city }}
        </span>
        <span v-else class="text-grey">-</span>
      </template>
    </v-data-table>
  </v-card>
</template>

<script setup lang="ts">
import { computed } from 'vue'

interface Log {
  timestamp: string
  type: string
  src_ip: string
  attack_tool?: string
  geoip?: {
    country: string
    city: string
  }
  message?: string
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
  { title: 'Timestamp', key: 'timestamp', sortable: true },
  { title: 'Type', key: 'type', sortable: true },
  { title: 'Source IP', key: 'src_ip', sortable: true },
  { title: 'Attack Tool', key: 'attack_tool', sortable: false },
  { title: 'Location', key: 'geoip', sortable: false },
  { title: 'Message', key: 'message', sortable: false }
]

function formatDate(timestamp: string) {
  return new Date(timestamp).toLocaleString()
}

function getTypeColor(type: string) {
  switch (type) {
    case 'attack': return 'error'
    case 'honeypot': return 'warning'
    case 'error': return 'info'
    default: return 'grey'
  }
}
</script>
