<template>
  <v-card class="mt-6 patterns-card" v-if="patterns.length > 0" elevation="2">
    <v-card-title class="d-flex align-center pa-4">
      <v-icon icon="mdi-chart-line" class="mr-2" size="24" />
      <span class="text-h6 font-weight-medium">Attack Patterns</span>
      <v-spacer />
      <v-chip color="warning" size="small" variant="flat">
        {{ patterns.length }} patterns
      </v-chip>
    </v-card-title>

    <v-data-table
      :headers="headers"
      :items="patterns"
      class="elevation-0"
      items-per-page="10"
    >
      <template v-slot:item.first_seen="{ item }">
        {{ formatDate(item.first_seen) }}
      </template>

      <template v-slot:item.last_seen="{ item }">
        {{ formatDate(item.last_seen) }}
      </template>

      <template v-slot:item.count="{ item }">
        <v-chip color="error" size="small" variant="flat">
          {{ item.count }}
        </v-chip>
      </template>
    </v-data-table>
  </v-card>
</template>

<script setup lang="ts">
interface Pattern {
  pattern: string
  count: number
  first_seen: string
  last_seen: string
}

interface Props {
  patterns: Pattern[]
}

const props = defineProps<Props>()

const headers = [
  { title: 'Pattern', key: 'pattern', sortable: true },
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

<style scoped>
.patterns-card {
  border-radius: 12px;
  overflow: hidden;
}

:deep(.v-data-table) {
  border-radius: 0 0 12px 12px;
}
</style>
