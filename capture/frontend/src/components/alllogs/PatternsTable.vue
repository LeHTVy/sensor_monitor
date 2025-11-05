<template>
  <v-card class="mt-6 patterns-card" v-if="patterns.length > 0" elevation="2" rounded="lg">
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
      :items-per-page="10"
      :items-per-page-options="[10, 25, 50]"
      hover
    >
      <template v-slot:item.first_seen="{ item }">
        <div class="d-flex flex-column">
          <span class="text-body-2">{{ formatDate(item.first_seen) }}</span>
          <span class="text-caption text-medium-emphasis">{{ formatTime(item.first_seen) }}</span>
        </div>
      </template>

      <template v-slot:item.last_seen="{ item }">
        <div class="d-flex flex-column">
          <span class="text-body-2">{{ formatDate(item.last_seen) }}</span>
          <span class="text-caption text-medium-emphasis">{{ formatTime(item.last_seen) }}</span>
        </div>
      </template>

      <template v-slot:item.count="{ item }">
        <v-chip color="error" size="small" variant="flat">
          <v-icon start size="16">mdi-counter</v-icon>
          {{ item.count }}
        </v-chip>
      </template>

      <template v-slot:item.pattern="{ item }">
        <code class="text-body-2">{{ item.pattern }}</code>
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
  { title: 'Count', key: 'count', sortable: true, width: '120px' },
  { title: 'First Seen', key: 'first_seen', sortable: true, width: '180px' },
  { title: 'Last Seen', key: 'last_seen', sortable: true, width: '180px' }
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
</script>

<style scoped>
.patterns-card {
  border-radius: 12px;
  overflow: hidden;
}

:deep(.v-data-table) {
  border-radius: 0 0 12px 12px;
}

:deep(.v-data-table__tr:hover) {
  background-color: rgba(var(--v-theme-primary), 0.05);
}

code {
  background-color: rgba(var(--v-theme-surface-variant), 0.5);
  padding: 4px 8px;
  border-radius: 4px;
  font-family: 'Courier New', monospace;
}
</style>

