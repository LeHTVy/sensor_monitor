<template>
  <v-row class="mb-6">
    <v-col
      v-for="card in statCards"
      :key="card.title"
      cols="12"
      sm="6"
      md="3"
    >
      <v-card class="pa-4" color="primary" variant="tonal">
        <v-card-text class="text-center">
          <div class="text-h3 font-weight-bold">{{ card.value }}</div>
          <div class="text-h6">{{ card.title }}</div>
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
</script>
