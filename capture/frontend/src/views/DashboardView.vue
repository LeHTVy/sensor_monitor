<template>
  <v-app>
    <v-app-bar color="primary" dark>
      <v-app-bar-title>
        <v-icon icon="mdi-shield-account" class="mr-2" />
        Capture Server Dashboard
      </v-app-bar-title>

      <v-spacer />

      <v-btn @click="toggleTheme" color="secondary" class="mr-2">
        <v-icon left>{{ isDark ? 'mdi-weather-sunny' : 'mdi-weather-night' }}</v-icon>
        {{ isDark ? 'Light' : 'Dark' }}
      </v-btn>

      <v-btn @click="authStore.logout" color="error">
        <v-icon left>mdi-logout</v-icon>
        Logout
      </v-btn>
    </v-app-bar>

    <v-main>
      <v-container fluid>
        <!-- Stats Cards -->
        <StatsCards />

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
        <LogsTable
          :logs="dashboardStore.logs"
          :loading="dashboardStore.loading"
          @refresh="refreshData"
        />

        <!-- Attack Patterns -->
        <PatternsTable :patterns="dashboardStore.patterns" />
      </v-container>
    </v-main>
  </v-app>
</template>

<script setup lang="ts">
import { onMounted, computed } from 'vue'
import { useTheme } from 'vuetify'
import { useAuthStore } from '@/stores/auth'
import { useDashboardStore } from '@/stores/dashboard'
import StatsCards from '@/components/StatsCards.vue'
import LogsTable from '@/components/LogsTable.vue'
import PatternsTable from '@/components/PatternsTable.vue'

const authStore = useAuthStore()
const dashboardStore = useDashboardStore()
const theme = useTheme()

const isDark = computed(() => theme.global.current.value.dark)

function toggleTheme() {
  theme.global.name.value = isDark.value ? 'light' : 'dark'
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
