<template>
  <v-card
    :class="['threat-capsule', { 'selected': selected }]"
    @click="$emit('click')"
    elevation="2"
    class="mb-2"
  >
    <v-card-text class="pa-3">
      <div class="d-flex align-center justify-space-between mb-2">
        <v-chip
          :color="getSeverityColor(log.threat_level)"
          size="x-small"
          variant="flat"
          class="font-weight-bold"
        >
          {{ log.threat_level?.toUpperCase() || 'UNKNOWN' }}
        </v-chip>
        <span class="text-caption text-medium-emphasis">
          {{ formatTime(log.timestamp) }}
        </span>
      </div>
      
      <div class="text-body-2 font-weight-bold mb-1">
        IP: {{ log.src_ip || log.ip }}
        <v-icon 
          v-if="log.geoip?.country" 
          size="small" 
          class="ml-1"
        >
          mdi-map-marker
        </v-icon>
      </div>
      
      <div class="text-caption mb-2">
        <span class="text-medium-emphasis">
          {{ log.geoip?.country || 'Unknown' }} | 
          {{ getCategoryLabel(log.category) }} | 
          Tool: {{ log.attack_tool || 'Unknown' }}
        </span>
      </div>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
defineProps<{ log: any, selected: boolean }>()
defineEmits(['click'])

function getSeverityColor(level?: string) {
  const colors: Record<string, string> = {
    critical: 'error',
    high: 'warning',
    medium: 'info',
    low: 'success'
  }
  return colors[level?.toLowerCase() || ''] || 'grey'
}

function getCategoryLabel(category?: string) {
  const labels: Record<string, string> = {
    reconnaissance: 'Reconnaissance',
    brute_force: 'Brute Force (SSH)',
    sql_injection: 'SQL Injection',
    command_injection: 'Command Injection',
    file_upload: 'File Upload Attack',
    path_traversal: 'Path Traversal',
    xss: 'XSS Attack'
  }
  return labels[category || ''] || category || 'Unknown'
}

function formatTime(timestamp?: string) {
  if (!timestamp) return 'Unknown'
  const date = new Date(timestamp)
  return date.toLocaleString('en-US', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  })
}
</script>

<style scoped>
.threat-capsule {
  cursor: pointer;
  transition: all 0.2s ease;
  border-left: 4px solid transparent;
}

.threat-capsule.selected {
  border-left-color: rgb(var(--v-theme-primary));
  background: rgba(var(--v-theme-primary), 0.1);
}

.threat-capsule:hover {
  transform: translateX(4px);
  box-shadow: 0 4px 12px rgba(var(--v-theme-primary), 0.2);
}
</style>
