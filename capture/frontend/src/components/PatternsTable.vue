<template>
  <v-card class="mt-6" v-if="patterns.length > 0">
    <v-card-title>
      <v-icon icon="mdi-chart-line" class="mr-2" />
      Attack Patterns
    </v-card-title>

    <v-data-table
      :headers="headers"
      :items="patterns"
      class="elevation-1"
    >
      <template #item.first_seen="{ item }">
        {{ formatDate(item.first_seen) }}
      </template>

      <template #item.last_seen="{ item }">
        {{ formatDate(item.last_seen) }}
      </template>
    </v-data-table>
  </v-card>
</template>

<script setup lang="ts">
interface Pattern {
  tool: string
  count: number
  first_seen: string
  last_seen: string
}

interface Props {
  patterns: Pattern[]
}

const props = defineProps<Props>()

const headers = [
  { title: 'Tool', key: 'tool', sortable: true },
  { title: 'Count', key: 'count', sortable: true },
  { title: 'First Seen', key: 'first_seen', sortable: true },
  { title: 'Last Seen', key: 'last_seen', sortable: true }
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
</script>
