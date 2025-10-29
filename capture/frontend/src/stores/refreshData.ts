import { defineStore } from 'pinia'
import { ref } from 'vue'
import { useDashboardStore } from './dashboard'

export const useRefreshStore = defineStore('refresh', () => {
  const dashboardStore = useDashboardStore()
  const refreshInterval = ref<ReturnType<typeof setInterval> | null>(null)
  const isRefreshing = ref(false)

  function startAutoRefresh(intervalMs: number = 1000) {
    if (refreshInterval.value) {
      clearInterval(refreshInterval.value)
    }

    refreshInterval.value = setInterval(() => {
      refreshData()
    }, intervalMs)
  }

  function stopAutoRefresh() {
    if (refreshInterval.value) {
      clearInterval(refreshInterval.value)
      refreshInterval.value = null
    }
  }

  async function refreshData() {
    if (isRefreshing.value) return

    isRefreshing.value = true
    try {
      await dashboardStore.loadAllData()
    } finally {
      isRefreshing.value = false
    }
  }

  return {
    refreshInterval,
    isRefreshing,
    startAutoRefresh,
    stopAutoRefresh,
    refreshData
  }
})
