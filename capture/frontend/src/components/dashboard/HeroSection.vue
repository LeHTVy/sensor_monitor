<template>
  <v-card class="hero-section" elevation="0" color="transparent">
    <v-card-text class="hero-content">
      <div class="hero-title">
        <v-icon icon="mdi-shield-check" size="64" class="mb-4 hero-icon" />
        <h1 class="text-h3 font-weight-bold mb-4">Capture Server Dashboard</h1>
        <p class="text-h6 text-medium-emphasis mb-6">
          Real-time security monitoring and threat analysis platform
        </p>
      </div>

      <!-- Time Period Selector -->
      <div class="d-flex justify-center mb-6">
        <v-btn-toggle
          v-model="selectedPeriod"
          mandatory
          density="compact"
          color="primary"
          @update:model-value="changePeriod"
        >
          <v-btn value="24">24h</v-btn>
          <v-btn value="168">7 days</v-btn>
          <v-btn value="720">30 days</v-btn>
        </v-btn-toggle>
      </div>

      <v-row class="hero-stats">
        <!-- High Severity Events -->
        <v-col cols="12" sm="6" md="3">
          <v-card class="stat-card" elevation="2" rounded="lg">
            <v-card-text class="text-center">
              <v-icon icon="mdi-alert-circle" size="32" color="error" class="mb-2" />
              <div class="text-h5 font-weight-bold">{{ stats.high_severity_count }}</div>
              <div class="text-caption text-medium-emphasis">High Severity</div>
            </v-card-text>
          </v-card>
        </v-col>

        <!-- Unique Attackers -->
        <v-col cols="12" sm="6" md="3">
          <v-card class="stat-card" elevation="2" rounded="lg">
            <v-card-text class="text-center">
              <v-icon icon="mdi-account-multiple" size="32" color="warning" class="mb-2" />
              <div class="text-h5 font-weight-bold">{{ stats.unique_attackers }}</div>
              <div class="text-caption text-medium-emphasis">Unique Attackers</div>
            </v-card-text>
          </v-card>
        </v-col>

        <!-- Top Attack Type -->
        <v-col cols="12" sm="6" md="3">
          <v-card class="stat-card" elevation="2" rounded="lg">
            <v-card-text class="text-center">
              <v-icon icon="mdi-tools" size="32" color="info" class="mb-2" />
              <div class="text-h5 font-weight-bold text-truncate">{{ stats.top_attack_type }}</div>
              <div class="text-caption text-medium-emphasis">Top Attack Type</div>
            </v-card-text>
          </v-card>
        </v-col>

        <!-- Most Targeted Port -->
        <v-col cols="12" sm="6" md="3">
          <v-card class="stat-card" elevation="2" rounded="lg">
            <v-card-text class="text-center">
              <v-icon icon="mdi-target" size="32" color="success" class="mb-2" />
              <div class="text-h5 font-weight-bold">{{ formatPort(stats.most_targeted_port) }}</div>
              <div class="text-caption text-medium-emphasis">Most Targeted</div>
            </v-card-text>
          </v-card>
        </v-col>
      </v-row>

      <div class="hero-description mt-8">
        <p class="text-body-1 text-medium-emphasis">
          {{ periodLabel }} • {{ stats.logs_in_period?.toLocaleString() || 0 }} events analyzed • {{ stats.total_logs_received?.toLocaleString() || 0 }} total logs
        </p>
      </div>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useDashboardStore } from '@/stores/dashboard'

const dashboardStore = useDashboardStore()

// Time period selection
const selectedPeriod = ref('24')

const stats = computed(() => dashboardStore.stats)

const periodLabel = computed(() => {
  switch (selectedPeriod.value) {
    case '24': return 'Last 24 hours'
    case '168': return 'Last 7 days'
    case '720': return 'Last 30 days'
    default: return 'Last 24 hours'
  }
})

function changePeriod(hours: string) {
  dashboardStore.setStatsPeriod(parseInt(hours))
}

function formatPort(port: number): string {
  if (!port) return 'N/A'
  const portNames: Record<number, string> = {
    22: ':22 SSH',
    80: ':80 HTTP',
    443: ':443 HTTPS',
    3306: ':3306 MySQL',
    5432: ':5432 PostgreSQL',
    6379: ':6379 Redis',
    27017: ':27017 MongoDB',
    8080: ':8080 HTTP-Alt'
  }
  return portNames[port] || `:${port}`
}
</script>

<style scoped>
.hero-section {
  text-align: center;
  padding: 48px 24px;
}

.hero-icon {
  color: rgb(var(--v-theme-primary));
  filter: drop-shadow(0 0 20px rgba(var(--v-theme-primary), 0.3));
}

.stat-card {
  background: rgba(var(--v-theme-surface), 0.8);
  border: 1px solid rgba(var(--v-theme-primary), 0.2);
  transition: all 0.3s ease;
}

.stat-card:hover {
  transform: translateY(-4px);
  border-color: rgba(var(--v-theme-primary), 0.5);
  box-shadow: 0 8px 24px rgba(var(--v-theme-primary), 0.2);
}
</style>
