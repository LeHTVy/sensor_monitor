import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8082'

// Interface for fetch params
interface FetchAttackersParams {
    limit?: number
    page?: number
    sort_by?: string
    order?: string
}

export const useAttackersStore = defineStore('attackers', () => {
    // State
    const attackers = ref([])
    const total = ref(0)
    const loading = ref(false)
    const error = ref<string | null>(null)
    const reconJobs = ref({}) // Map of reconId -> recon status
    const reconResults = ref({}) // Map of reconId -> full results

    // Computed
    const activeReconJobs = computed(() => {
        return Object.values(reconJobs.value).filter(
            (job: any) => job.status === 'running' || job.status === 'queued'
        ).length
    })

    const completedScans = computed(() => {
        return Object.values(reconJobs.value).filter(
            (job: any) => job.status === 'completed'
        ).length
    })

    // Actions
    async function fetchAttackers(params: FetchAttackersParams = {}) {
        loading.value = true
        error.value = null

        try {
            const apiKey = localStorage.getItem('api_key')

            if (!apiKey) {
                throw new Error('No API key found. Please log in again.')
            }

            console.log('Fetching attackers with params:', params)

            const response = await axios.get(`${API_URL}/api/attackers`, {
                params: {
                    limit: params.limit || 500,
                    page: params.page || 1,
                    sort_by: params.sort_by || 'total_attacks',
                    order: params.order || 'desc'
                },
                headers: {
                    'X-API-Key': apiKey
                }
            })

            console.log('Attackers API response:', response.data)

            attackers.value = response.data.attackers || []
            total.value = response.data.total || 0

            console.log(`✅ Fetched ${attackers.value.length} attackers out of ${total.value} total`)
        } catch (err: any) {
            console.error('Failed to fetch attackers:', err)
            error.value = err.response?.data?.error || err.message || 'Failed to load attackers data'

            // Show specific error messages
            if (err.response?.status === 503) {
                error.value = 'Elasticsearch not configured on backend'
            } else if (err.response?.status === 401) {
                error.value = 'Authentication failed. Please log in again.'
            }

            throw err
        } finally {
            loading.value = false
        }
    }

    async function startRecon(targetIp: string, scanTypes: string[] = ['nmap', 'amass', 'subfinder', 'bbot']) {
        try {
            const apiKey = localStorage.getItem('api_key')

            const response = await axios.post(
                `${API_URL}/api/recon/start`,
                {
                    target_ip: targetIp,
                    scan_types: scanTypes
                },
                {
                    headers: {
                        'X-API-Key': apiKey,
                        'Content-Type': 'application/json'
                    }
                }
            )

            const reconId = response.data.recon_id

            // Initialize recon job in store
            reconJobs.value[reconId] = {
                recon_id: reconId,
                target_ip: targetIp,
                status: response.data.status,
                scan_types: scanTypes,
                start_time: new Date().toISOString()
            }

            console.log('Started recon:', reconId)
            return reconId
        } catch (error) {
            console.error('Failed to start reconnaissance:', error)
            throw error
        }
    }

    async function pollReconStatus(reconId: string) {
        try {
            const apiKey = localStorage.getItem('api_key')

            const response = await axios.get(
                `${API_URL}/api/recon/status/${reconId}`,
                {
                    headers: {
                        'X-API-Key': apiKey
                    }
                }
            )

            // Update job status
            reconJobs.value[reconId] = {
                ...reconJobs.value[reconId],
                ...response.data
            }

            // If completed, fetch full results
            if (response.data.status === 'completed' && !reconResults.value[reconId]) {
                await fetchReconResults(reconId)
            }

            return response.data
        } catch (error) {
            console.error('Failed to poll recon status:', error)
            throw error
        }
    }

    async function fetchReconResults(reconId: string) {
        try {
            const apiKey = localStorage.getItem('api_key')

            const response = await axios.get(
                `${API_URL}/api/recon/results/${reconId}`,
                {
                    headers: {
                        'X-API-Key': apiKey
                    }
                }
            )

            reconResults.value[reconId] = response.data

            return response.data
        } catch (error) {
            console.error('Failed to fetch recon results:', error)
            throw error
        }
    }

    async function downloadReport(reconId: string, format: 'docx' | 'pdf' = 'docx') {
        try {
            const apiKey = localStorage.getItem('api_key')

            const response = await axios.get(
                `${API_URL}/api/recon/report/${reconId}/download`,
                {
                    params: { format },
                    headers: {
                        'X-API-Key': apiKey
                    },
                    responseType: 'blob'
                }
            )

            // Create download link
            const url = window.URL.createObjectURL(new Blob([response.data]))
            const link = document.createElement('a')
            link.href = url

            // Extract filename from Content-Disposition header if available
            const contentDisposition = response.headers['content-disposition']
            let filename = `recon_report_${reconId}.${format}`

            if (contentDisposition) {
                const filenameMatch = contentDisposition.match(/filename="?([^"]+)"?/)
                if (filenameMatch && filenameMatch[1]) {
                    filename = filenameMatch[1]
                }
            }

            link.setAttribute('download', filename)
            document.body.appendChild(link)
            link.click()
            document.body.removeChild(link)

            console.log('Downloaded report:', filename)
        } catch (error) {
            console.error('Failed to download report:', error)
            throw error
        }
    }

    function getReconStatus(reconId: string) {
        return reconJobs.value[reconId] || null
    }

    function getReconResults(reconId: string) {
        return reconResults.value[reconId] || null
    }

    async function updateReconJobsStatus() {
        // Update status for all active recon jobs
        const activeJobs = Object.keys(reconJobs.value).filter(
            id => {
                const job = reconJobs.value[id]
                return job.status === 'running' || job.status === 'queued'
            }
        )

        for (const reconId of activeJobs) {
            try {
                await pollReconStatus(reconId)
            } catch (error) {
                console.error(`Failed to update status for ${reconId}:`, error)
            }
        }
    }

    return {
        attackers,
        reconJobs,
        reconResults,
        total,
        loading,
        error,
        activeReconJobs,
        completedScans,
        fetchAttackers,
        startRecon,
        pollReconStatus,
        fetchReconResults,
        downloadReport,
        getReconStatus,
        getReconResults,
        updateReconJobsStatus
    }
})
