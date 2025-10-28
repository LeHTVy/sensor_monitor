import { createStore } from 'vuex'

export default createStore({
  state: {
    isAuthenticated: !!localStorage.getItem('capture_api_key'),
    apiKey: localStorage.getItem('capture_api_key'),
    user: localStorage.getItem('capture_user') ? JSON.parse(localStorage.getItem('capture_user')) : null,
    logs: [],
    stats: {
      total_logs_received: 0,
      attack_logs: 0,
      honeypot_logs: 0,
      error_logs: 0
    },
    patterns: [],
    currentFilter: 'all',
    loading: false
  },
  mutations: {
    SET_AUTHENTICATED(state, { isAuthenticated, apiKey, user }) {
      state.isAuthenticated = isAuthenticated
      state.apiKey = apiKey
      state.user = user
    },
    SET_LOGS(state, logs) {
      state.logs = logs
    },
    SET_STATS(state, stats) {
      state.stats = stats
    },
    SET_PATTERNS(state, patterns) {
      state.patterns = patterns
    },
    SET_FILTER(state, filter) {
      state.currentFilter = filter
    },
    SET_LOADING(state, loading) {
      state.loading = loading
    }
  },
  actions: {
    async login({ commit }, { username, password }) {
      try {
        const response = await fetch('/api/auth/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ username, password })
        })
        
        const data = await response.json()
        console.log('Login response:', data) // Debug log
        
        if (data.success && data.api_key) {
          commit('SET_AUTHENTICATED', {
            isAuthenticated: true,
            apiKey: data.api_key,
            user: { username, role: 'admin' }
          })
          
          // Save to localStorage
          localStorage.setItem('capture_api_key', data.api_key)
          localStorage.setItem('capture_user', JSON.stringify({ username, role: 'admin' }))
          
          console.log('API Key saved:', data.api_key) // Debug log
          return { success: true, apiKey: data.api_key }
        } else {
          console.error('Login failed:', data.message)
          return { success: false, message: data.message }
        }
      } catch (error) {
        return { success: false, message: error.message }
      }
    },
    
    logout({ commit }) {
      commit('SET_AUTHENTICATED', {
        isAuthenticated: false,
        apiKey: null,
        user: null
      })
      
      localStorage.removeItem('capture_api_key')
      localStorage.removeItem('capture_user')
    },
    
    async loadStats({ commit, state }) {
      if (!state.isAuthenticated || !state.apiKey) {
        console.log('loadStats: Not authenticated or no API key', { isAuthenticated: state.isAuthenticated, apiKey: state.apiKey })
        return
      }
      
      console.log('loadStats: Making request with API key:', state.apiKey)
      
      try {
        const response = await fetch('/api/stats', {
          headers: {
            'X-API-Key': state.apiKey
          }
        })
        
        if (response.ok) {
          const data = await response.json()
          commit('SET_STATS', data.stats)
        } else if (response.status === 401) {
          // API key invalid, logout
          commit('SET_AUTHENTICATED', {
            isAuthenticated: false,
            apiKey: null,
            user: null
          })
          localStorage.removeItem('capture_api_key')
          localStorage.removeItem('capture_user')
        }
      } catch (error) {
        console.error('Error loading stats:', error)
      }
    },
    
    async loadLogs({ commit, state }) {
      if (!state.isAuthenticated || !state.apiKey) return
      
      try {
        const url = state.currentFilter === 'all' 
          ? '/api/logs' 
          : `/api/logs?type=${state.currentFilter}`
          
        const response = await fetch(url, {
          headers: {
            'X-API-Key': state.apiKey
          }
        })
        
        if (response.ok) {
          const data = await response.json()
          commit('SET_LOGS', data.logs || [])
        } else if (response.status === 401) {
          // API key invalid, logout
          commit('SET_AUTHENTICATED', {
            isAuthenticated: false,
            apiKey: null,
            user: null
          })
          localStorage.removeItem('capture_api_key')
          localStorage.removeItem('capture_user')
        }
      } catch (error) {
        console.error('Error loading logs:', error)
      }
    },
    
    async loadPatterns({ commit, state }) {
      if (!state.isAuthenticated || !state.apiKey) return
      
      try {
        const response = await fetch('/api/attack-patterns', {
          headers: {
            'X-API-Key': state.apiKey
          }
        })
        
        if (response.ok) {
          const data = await response.json()
          commit('SET_PATTERNS', data.patterns || [])
        } else if (response.status === 401) {
          // API key invalid, logout
          commit('SET_AUTHENTICATED', {
            isAuthenticated: false,
            apiKey: null,
            user: null
          })
          localStorage.removeItem('capture_api_key')
          localStorage.removeItem('capture_user')
        }
      } catch (error) {
        console.error('Error loading patterns:', error)
      }
    },
    
    setFilter({ commit }, filter) {
      commit('SET_FILTER', filter)
    }
  }
})
