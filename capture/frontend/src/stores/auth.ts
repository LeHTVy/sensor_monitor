import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

export interface User {
  username: string
  role: string
}

export const useAuthStore = defineStore('auth', () => {
  const isAuthenticated = ref(!!localStorage.getItem('capture_api_key'))
  const apiKey = ref(localStorage.getItem('capture_api_key'))
  const user = ref<User | null>(
    localStorage.getItem('capture_user')
      ? JSON.parse(localStorage.getItem('capture_user') as string)
      : null
  )

  const isLoggedIn = computed(() => isAuthenticated.value && !!apiKey.value)

  async function login(username: string, password: string) {
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
      })

      const data = await response.json()

      if (data.success && data.api_key) {
        isAuthenticated.value = true
        apiKey.value = data.api_key
        user.value = { username, role: 'admin' }

        localStorage.setItem('capture_api_key', data.api_key)
        localStorage.setItem('capture_user', JSON.stringify({ username, role: 'admin' }))

        return { success: true, apiKey: data.api_key }
      } else {
        return { success: false, message: data.message }
      }
    } catch (error: any) {
      return { success: false, message: error.message }
    }
  }

  function logout() {
    isAuthenticated.value = false
    apiKey.value = null
    user.value = null

    localStorage.removeItem('capture_api_key')
    localStorage.removeItem('capture_user')
  }

  return {
    isAuthenticated,
    apiKey,
    user,
    isLoggedIn,
    login,
    logout
  }
})
