<template>
  <v-card class="filter-panel" elevation="2" rounded="lg">
    <v-card-title class="d-flex align-center pa-4">
      <v-icon icon="mdi-filter" class="mr-2" />
      <span class="text-h6 font-weight-medium">Filters</span>
    </v-card-title>

    <v-divider />

    <!-- Category Tabs -->
    <v-tabs
      v-model="currentFilter"
      @update:model-value="onFilterChange"
      color="primary"
      align-tabs="center"
      bg-color="transparent"
      class="pa-2"
    >
      <v-tab value="all" class="text-capitalize">
        <v-icon start>mdi-format-list-bulleted</v-icon>
        All Logs
      </v-tab>
      <v-tab value="attack" class="text-capitalize">
        <v-icon start>mdi-shield-alert</v-icon>
        Attacks
      </v-tab>
      <v-tab value="honeypot" class="text-capitalize">
        <v-icon start>mdi-bee</v-icon>
        Honeypot
      </v-tab>
      <v-tab value="traffic" class="text-capitalize">
        <v-icon start>mdi-traffic-light</v-icon>
        Traffic
      </v-tab>
    </v-tabs>

    <v-divider />

    <!-- Date Filter -->
    <v-card-text class="pa-4">
      <div class="d-flex align-center mb-3">
        <v-icon icon="mdi-calendar-filter" class="mr-2" />
        <span class="text-subtitle-1 font-weight-medium">Date Range</span>
      </div>
      
      <v-row dense>
        <v-col cols="12" sm="6">
          <v-text-field
            v-model="dateFrom"
            type="date"
            label="From Date"
            density="compact"
            variant="outlined"
            prepend-inner-icon="mdi-calendar-start"
            hide-details="auto"
            @update:model-value="onDateChange"
          />
        </v-col>
        <v-col cols="12" sm="6">
          <v-text-field
            v-model="dateTo"
            type="date"
            label="To Date"
            density="compact"
            variant="outlined"
            prepend-inner-icon="mdi-calendar-end"
            hide-details="auto"
            @update:model-value="onDateChange"
          />
        </v-col>
      </v-row>

      <v-btn
        v-if="dateFrom || dateTo"
        @click="clearDateFilter"
        color="error"
        size="small"
        variant="text"
        block
        class="mt-2"
      >
        <v-icon start>mdi-close</v-icon>
        Clear Date Filter
      </v-btn>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import { useDashboardStore } from '@/stores/dashboard'

const dashboardStore = useDashboardStore()

const currentFilter = ref<'all' | 'attack' | 'honeypot' | 'traffic'>(dashboardStore.currentFilter)
const dateFrom = ref<string | null>(dashboardStore.dateFrom)
const dateTo = ref<string | null>(dashboardStore.dateTo)

watch(() => dashboardStore.currentFilter, (newValue) => {
  currentFilter.value = newValue
})

watch(() => dashboardStore.dateFrom, (newValue) => {
  dateFrom.value = newValue
})

watch(() => dashboardStore.dateTo, (newValue) => {
  dateTo.value = newValue
})

function onFilterChange(value: 'all' | 'attack' | 'honeypot' | 'traffic') {
  dashboardStore.setFilter(value)
}

function onDateChange() {
  dashboardStore.loadLogs()
}

function clearDateFilter() {
  dashboardStore.clearDateFilter()
  dateFrom.value = null
  dateTo.value = null
}
</script>

<style scoped>
.filter-panel {
  border-radius: 12px;
  overflow: hidden;
}

:deep(.v-tabs) {
  background-color: transparent;
}

:deep(.v-tab) {
  min-width: 120px;
  font-weight: 500;
}
</style>

