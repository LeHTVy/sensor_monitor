<template>
  <v-app>
    <Navbar />
    <v-main>
      <v-container fluid class="attackers-view fill-height pa-0">
        <v-row no-gutters class="fill-height">
      <!-- Main Content -->
      <v-col cols="12" class="d-flex flex-column h-100">
        <!-- Toolbar -->
        <div class="d-flex align-center justify-space-between pa-4 border-b bg-surface">
          <div>
            <h1 class="text-h5 font-weight-bold">Attackers</h1>
            <p class="text-caption text-medium-emphasis">Unique attacker IPs identified from Elasticsearch</p>
          </div>
          <v-btn @click="fetchAttackers" :loading="loading" color="primary" prepend-icon="mdi-refresh">
            Refresh
          </v-btn>
        </div>

        <!-- Stats Cards -->
        <div class="pa-4 border-b">
          <v-row>
            <v-col cols="12" md="3">
              <v-card>
                <v-card-text>
                  <div class="text-overline mb-1">Total Attackers</div>
                  <div class="text-h4">{{ total }}</div>
                </v-card-text>
              </v-card>
            </v-col>
            <v-col cols="12" md="3">
              <v-card>
                <v-card-text>
                  <div class="text-overline mb-1">Completed Scans</div>
                  <div class="text-h4 text-success">{{ completedScans }}</div>
                </v-card-text>
              </v-card>
            </v-col>
            <v-col cols="12" md="6">
              <ReconTechniquesChart />
            </v-col>
          </v-row>
        </div>

        <!-- Filters and Search -->
        <div class="pa-4 border-b">
          <v-row>
            <v-col cols="12" md="6">
              <v-text-field
                v-model="searchQuery"
                label="Search by IP, Country, or ISP"
                prepend-inner-icon="mdi-magnify"
                variant="outlined"
                density="compact"
                hide-details
                clearable
              ></v-text-field>
            </v-col>
            <v-col cols="12" md="3">
              <v-select
                v-model="sortBy"
                :items="sortOptions"
                label="Sort By"
                variant="outlined"
                density="compact"
                hide-details
                @update:model-value="fetchAttackers"
              ></v-select>
            </v-col>
            <v-col cols="12" md="3">
              <v-select
                v-model="sortOrder"
                :items="[{title: 'Descending', value: 'desc'}, {title: 'Ascending', value: 'asc'}]"
                label="Order"
                variant="outlined"
                density="compact"
                hide-details
                @update:model-value="fetchAttackers"
              ></v-select>
            </v-col>
          </v-row>
        </div>

        <!-- Error Alert -->
        <v-alert
          v-if="attackersStore.error"
          type="error"
          variant="tonal"
          class="ma-4"
          closable
          @click:close="attackersStore.error = null"
        >
          <strong>Error loading attackers:</strong> {{ attackersStore.error }}
        </v-alert>

        <!-- Data Table -->
        <div class="flex-grow-1 overflow-auto">
          <v-data-table
            :headers="headers"
            :items="filteredAttackers"
            :loading="loading"
            v-model:items-per-page="itemsPerPage"
            hover
            density="comfortable"
            class="h-100"
            fixed-header
          >
            <!-- IP Column -->
            <template v-slot:item.ip="{ item }">
              <span class="font-weight-medium">{{ item.ip }}</span>
            </template>

            <!-- Country Column -->
            <template v-slot:item.country="{ item }">
              <v-chip size="small" variant="outlined">
                {{ item.country }}
              </v-chip>
            </template>

            <!-- Threat Score Column -->
            <template v-slot:item.max_threat_score="{ item }">
              <v-chip
                :color="getThreatColor(item.max_threat_score)"
                size="small"
                variant="flat"
              >
                {{ item.max_threat_score }}
              </v-chip>
            </template>

            <!-- Total Attacks Column -->
            <template v-slot:item.total_attacks="{ item }">
              <span class="font-weight-bold">{{ item.total_attacks }}</span>
            </template>

            <!-- First Seen Column -->
            <template v-slot:item.first_seen="{ item }">
              {{ formatDate(item.first_seen) }}
            </template>

            <!-- Last Seen Column -->
            <template v-slot:item.last_seen="{ item }">
              {{ formatDate(item.last_seen) }}
            </template>

            <!-- Actions Column -->
            <template v-slot:item.actions="{ item }">
              <v-btn
                @click="startReconnaissance(item)"
                color="primary"
                size="small"
                variant="tonal"
                prepend-icon="mdi-radar"
              >
                Run Recon
              </v-btn>
            </template>
          </v-data-table>
        </div>
      </v-col>
    </v-row>

    <!-- Reconnaissance Progress Modal -->
    <ReconProgressModal
      v-if="selectedAttacker"
      v-model="showReconModal"
      :attacker="selectedAttacker"
      :recon-id="currentReconId"
      @close="handleReconClose"
    />
  </v-container>
    </v-main>
  </v-app>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useAttackersStore } from '../stores/attackers'
import Navbar from '@/components/Navbar.vue'
import ReconProgressModal from '@/components/ReconProgressModal.vue'
import ReconTechniquesChart from '@/components/attackers/ReconTechniquesChart.vue'

const attackersStore = useAttackersStore()

// Data
const searchQuery = ref('')
const sortBy = ref('total_attacks')
const sortOrder = ref('desc')
const itemsPerPage = ref(25)
const showReconModal = ref(false)
const selectedAttacker = ref(null)
const currentReconId = ref('')

// Table headers
const headers = [
  { title: 'IP Address', key: 'ip', width: '150px' },
  { title: 'Country', key: 'country', width: '120px' },
  { title: 'City', key: 'city', width: '120px' },
  { title: 'ISP', key: 'isp', width: '200px' },
  { title: 'Threat Score', key: 'max_threat_score', width: '120px' },
  { title: 'Total Attacks', key: 'total_attacks', width: '130px' },
  { title: 'First Seen', key: 'first_seen', width: '150px' },
  { title: 'Last Seen', key: 'last_seen', width: '150px' },
  { title: 'Actions', key: 'actions', width: '150px', sortable: false }
]

// Sort options
const sortOptions = [
  { title: 'Total Attacks', value: 'total_attacks' },
  { title: 'Threat Score', value: 'threat_score' },
  { title: 'Last Seen', value: 'last_seen' },
  { title: 'First Seen', value: 'first_seen' }
]

// Computed
const loading = computed(() => attackersStore.loading)
const attackers = computed(() => attackersStore.attackers)
const total = computed(() => attackersStore.total)
const activeReconJobs = computed(() => attackersStore.activeReconJobs)
const completedScans = computed(() => attackersStore.completedScans)

const filteredAttackers = computed(() => {
  if (!searchQuery.value) return attackers.value

  const query = searchQuery.value.toLowerCase()
  return attackers.value.filter(attacker =>
    attacker.ip.toLowerCase().includes(query) ||
    attacker.country.toLowerCase().includes(query) ||
    attacker.city.toLowerCase().includes(query) ||
    attacker.isp.toLowerCase().includes(query)
  )
})

const highThreatCount = computed(() => {
  return attackers.value.filter(a => a.max_threat_score >= 70).length
})

// Methods
const fetchAttackers = async () => {
  await attackersStore.fetchAttackers({
    limit: 500,  // Load all unique attackers
    sort_by: sortBy.value,
    order: sortOrder.value
  })
}

const startReconnaissance = async (attacker: any) => {
  selectedAttacker.value = attacker
  showReconModal.value = true  // Show modal immediately
  currentReconId.value = 'pending'  // Temporary ID
  
  try {
    const reconId = await attackersStore.startRecon(attacker.ip, ['nmap', 'amass', 'subfinder', 'bbot'])
    currentReconId.value = reconId
  } catch (error: any) {
    console.error('Failed to start reconnaissance:', error)
    // Set error state in the modal
    currentReconId.value = 'error'
    // Store error in attackers store for display
    attackersStore.reconJobs['error'] = {
      recon_id: 'error',
      target_ip: attacker.ip,
      status: 'error',
      error: error.response?.data?.error || error.message || 'Failed to start reconnaissance. Server returned 500 error.'
    }
  }
}

const handleReconClose = () => {
  showReconModal.value = false
  selectedAttacker.value = null
  currentReconId.value = ''
}

const getThreatColor = (score: number): string => {
  if (score >= 80) return 'error'
  if (score >= 60) return 'warning'
  if (score >= 40) return 'info'
  return 'success'
}

const formatDate = (dateStr: string): string => {
  if (!dateStr) return 'N/A'
  try {
    const date = new Date(dateStr)
    return date.toLocaleString()
  } catch {
    return dateStr
  }
}

// Lifecycle
onMounted(() => {
  fetchAttackers()
  attackersStore.fetchReconStats()  // Fetch persisted recon stats
  
  // Periodically update recon job status and stats
  setInterval(() => {
    attackersStore.updateReconJobsStatus()
    attackersStore.fetchReconStats()  // Refresh from Elasticsearch
  }, 10000)
})
</script>

<style scoped>
.attackers-view {
  background: rgb(var(--v-theme-surface));
}

.border-b {
  border-bottom: 1px solid rgba(var(--v-border-color), var(--v-border-opacity));
}

.bg-surface {
  background: rgb(var(--v-theme-surface));
}

.font-weight-medium {
  font-weight: 500;
}
</style>
