<template>
  <v-row class="mb-6">
    <v-col
      v-for="(card, index) in statCards"
      :key="card.title"
      cols="12"
      sm="6"
      md="3"
    >
      <v-card 
        class="stat-card pa-4" 
        :color="getCardColor(index)"
        variant="tonal"
        elevation="2"
      >
        <v-card-text class="text-center pa-4">
          <div class="text-h2 font-weight-bold mb-2">{{ formatNumber(card.value) }}</div>
          <div class="text-subtitle-1 font-weight-medium">{{ card.title }}</div>
        </v-card-text>
      </v-card>
    </v-col>
  </v-row>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useDashboardStore } from '@/stores/dashboard'

const dashboardStore = useDashboardStore()

const statCards = computed(() => dashboardStore.statCards)

function getCardColor(index: number) {
  const colors = ['primary', 'error', 'warning', 'info']
  return colors[index % colors.length]
}

function formatNumber(value: number) {
  return new Intl.NumberFormat('vi-VN').format(value)
}
</script>

<style scoped>
.stat-card {
  border-radius: 16px;
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.stat-card:hover {
  transform: translateY(-4px);
  box-shadow: 0 8px 16px rgba(0, 0, 0, 0.2) !important;
}
</style>
