<template>
  <v-app>
    <v-app-bar color="primary" dark>
      <v-app-bar-title>
        <v-icon icon="mdi-shield-account" class="mr-2" />
        Capture Server Dashboard
      </v-app-bar-title>

      <v-spacer />

      <v-btn @click="authStore.logout" color="error">
        <v-icon left>mdi-logout</v-icon>
        Logout
      </v-btn>
    </v-app-bar>

    <v-main>
      <v-container fluid>
        <!-- Stats Cards -->
        <v-row class="mb-6">
          <v-col
            v-for="card in dashboardStore.statCards"
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

        <!-- Filter Tabs -->
        <v-card class="mb-6">
          <v-tabs
            v-model="dashboardStore.currentFilter"
            @update:model-value="(value: 'all' | 'attack' | 'honeypot' | 'error') => dashboardStore.setFilter(value)"
            color="primary"
            align-tabs="center"
          >
            <v-tab value="all">All Logs</v-tab>
            <v-tab value="attack">Attacks</v-tab>
            <v-tab value="honeypot">Honeypot</v-tab>
            <v-tab value="error">Errors</v-tab>
          </v-tabs>
        </v-card>

        <!-- Logs Table -->
        <v-card>
          <v-card-title>
            <v-icon icon="mdi-file-document-multiple" class="mr-2" />
            Logs
            <v-spacer />
            <v-btn
              @click="refreshData"
              :loading="dashboardStore.loading"
              color="primary"
              variant="outlined"
            >
              <v-icon left>mdi-refresh</v-icon>
              Refresh
            </v-btn>
          </v-card-title>

          <v-data-table
            :headers="headers"
            :items="dashboardStore.logs"
            :loading="dashboardStore.loading"
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

        <!-- Attack Patterns -->
        <v-card class="mt-6" v-if="dashboardStore.patterns.length > 0">
          <v-card-title>
            <v-icon icon="mdi-chart-line" class="mr-2" />
            Attack Patterns
          </v-card-title>

          <v-data-table
            :headers="patternHeaders"
            :items="dashboardStore.patterns"
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
      </v-container>
    </v-main>
  </v-app>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { useDashboardStore } from '@/stores/dashboard'

const authStore = useAuthStore()
const dashboardStore = useDashboardStore()

const headers = [
  { title: 'Timestamp', key: 'timestamp', sortable: true },
  { title: 'Type', key: 'type', sortable: true },
  { title: 'Source IP', key: 'src_ip', sortable: true },
  { title: 'Attack Tool', key: 'attack_tool', sortable: false },
  { title: 'Location', key: 'geoip', sortable: false },
  { title: 'Message', key: 'message', sortable: false }
]

const patternHeaders = [
  { title: 'Tool', key: 'tool', sortable: true },
  { title: 'Count', key: 'count', sortable: true },
  { title: 'First Seen', key: 'first_seen', sortable: true },
  { title: 'Last Seen', key: 'last_seen', sortable: true }
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

function refreshData() {
  dashboardStore.loadAllData()
}

onMounted(() => {
  if (authStore.isLoggedIn) {
    refreshData()
  }
})
</script>
