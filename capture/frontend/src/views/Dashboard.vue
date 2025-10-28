<template>
  <v-container fluid>
    <!-- Header Stats -->
    <v-row class="mb-4">
      <v-col cols="12" md="3" v-for="stat in statCards" :key="stat.title">
        <v-card color="primary" dark>
          <v-card-text>
            <div class="text-h4">{{ stat.value }}</div>
            <div>{{ stat.title }}</div>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>

    <!-- Filter Tabs -->
    <v-row class="mb-4">
      <v-col cols="12">
        <v-card>
          <v-tabs
            v-model="currentFilter"
            @update:model-value="handleFilterChange"
            color="primary"
          >
            <v-tab value="all">All Logs</v-tab>
            <v-tab value="attack">Attacks</v-tab>
            <v-tab value="honeypot">Honeypot</v-tab>
            <v-tab value="error">Errors</v-tab>
          </v-tabs>
        </v-card>
      </v-col>
    </v-row>

    <!-- Main Content -->
    <v-row>
      <!-- Logs Column -->
      <v-col cols="12" md="8">
        <v-card>
          <v-card-title>
            <v-icon class="mr-2">mdi-file-document-multiple</v-icon>
            Recent Logs
          </v-card-title>
          
          <v-card-text>
            <v-list>
              <v-list-item
                v-for="(log, index) in logs"
                :key="index"
                class="mb-2"
              >
                <v-list-item-content>
                  <v-list-item-title>{{ log.message || 'No message' }}</v-list-item-title>
                  <v-list-item-subtitle>
                    {{ formatTimestamp(log.timestamp) }} - {{ log.src_ip }}
                  </v-list-item-subtitle>
                </v-list-item-content>
                
                <v-list-item-action>
                  <v-chip
                    :color="getLogTypeColor(log.type)"
                    small
                  >
                    {{ log.type }}
                  </v-chip>
                </v-list-item-action>
              </v-list-item>
              
              <v-list-item v-if="logs.length === 0">
                <v-list-item-content>
                  <v-list-item-title class="text-center text-grey">
                    No logs available
                  </v-list-item-title>
                </v-list-item-content>
              </v-list-item>
            </v-list>
          </v-card-text>
        </v-card>
      </v-col>

      <!-- Attack Patterns Column -->
      <v-col cols="12" md="4">
        <v-card>
          <v-card-title>
            <v-icon class="mr-2">mdi-shield-alert</v-icon>
            Attack Patterns
          </v-card-title>
          
          <v-card-text>
            <v-list>
              <v-list-item
                v-for="(pattern, index) in patterns"
                :key="index"
                class="mb-2"
              >
                <v-list-item-content>
                  <v-list-item-title>{{ pattern.tool }}</v-list-item-title>
                  <v-list-item-subtitle>
                    Count: {{ pattern.count }}
                  </v-list-item-subtitle>
                </v-list-item-content>
              </v-list-item>
              
              <v-list-item v-if="patterns.length === 0">
                <v-list-item-content>
                  <v-list-item-title class="text-center text-grey">
                    No patterns detected
                  </v-list-item-title>
                </v-list-item-content>
              </v-list-item>
            </v-list>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>

<script>
import { computed, onMounted, onUnmounted } from 'vue'
import { useStore } from 'vuex'

export default {
  name: 'Dashboard',
  setup() {
    const store = useStore()
    
    const currentFilter = computed({
      get: () => store.state.currentFilter,
      set: (value) => store.dispatch('setFilter', value)
    })
    
    const logs = computed(() => store.state.logs)
    const patterns = computed(() => store.state.patterns)
    const stats = computed(() => store.state.stats)
    
    const statCards = computed(() => [
      { title: 'Total Logs', value: stats.value.total_logs_received },
      { title: 'Attacks', value: stats.value.attack_logs },
      { title: 'Honeypot', value: stats.value.honeypot_logs },
      { title: 'Errors', value: stats.value.error_logs }
    ])
    
    const handleFilterChange = (filter) => {
      store.dispatch('setFilter', filter)
      store.dispatch('loadLogs')
    }
    
    const formatTimestamp = (timestamp) => {
      if (!timestamp) return 'N/A'
      return new Date(timestamp).toLocaleString()
    }
    
    const getLogTypeColor = (type) => {
      const colors = {
        attack: 'error',
        honeypot: 'warning',
        error: 'error',
        suspicious: 'warning'
      }
      return colors[type] || 'primary'
    }
    
    const loadData = () => {
      store.dispatch('loadStats')
      store.dispatch('loadLogs')
      store.dispatch('loadPatterns')
    }
    
    let refreshInterval
    
    onMounted(() => {
      // Only load data if authenticated and has API key
      if (store.state.isAuthenticated && store.state.apiKey) {
        console.log('Dashboard mounted, loading data with API key:', store.state.apiKey)
        loadData()
        // Auto-refresh every 5 seconds
        refreshInterval = setInterval(loadData, 5000)
      } else {
        console.log('Dashboard mounted but not authenticated or no API key')
      }
    })
    
    onUnmounted(() => {
      if (refreshInterval) {
        clearInterval(refreshInterval)
      }
    })
    
    return {
      currentFilter,
      logs,
      patterns,
      statCards,
      handleFilterChange,
      formatTimestamp,
      getLogTypeColor
    }
  }
}
</script>
