<template>
  <v-container fluid class="fill-height">
    <v-row justify="center" align="center" class="fill-height">
      <v-col cols="12" sm="8" md="6" lg="4">
        <v-card class="pa-6" elevation="8">
          <v-card-title class="text-h4 text-center mb-6">
            <v-icon icon="mdi-shield-account" class="mr-2" color="primary" />
            Capture Server
          </v-card-title>

          <v-alert
            v-if="sessionExpired"
            type="warning"
            variant="tonal"
            class="mb-4"
            closable
            @click:close="sessionExpired = false"
          >
            Your session has expired. Please login again.
          </v-alert>

          <v-form @submit.prevent="handleLogin" ref="form">
            <v-text-field
              v-model="username"
              label="Username"
              prepend-inner-icon="mdi-account"
              variant="outlined"
              :rules="[v => !!v || 'Username is required']"
              class="mb-4"
            />

            <v-text-field
              v-model="password"
              label="Password"
              type="password"
              prepend-inner-icon="mdi-lock"
              variant="outlined"
              :rules="[v => !!v || 'Password is required']"
              class="mb-6"
            />

            <v-btn
              type="submit"
              color="primary"
              size="large"
              block
              :loading="loading"
              class="mb-4"
            >
              <v-icon left>mdi-login</v-icon>
              Login
            </v-btn>
          </v-form>

          <v-alert
            v-if="error"
            type="error"
            variant="tonal"
            class="mt-4"
          >
            {{ error }}
            <span v-if="attemptsRemaining !== null && attemptsRemaining > 0" class="ml-1">
              ({{ attemptsRemaining }} attempts remaining)
            </span>
          </v-alert>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()

const username = ref('')
const password = ref('')
const loading = ref(false)
const error = ref('')
const sessionExpired = ref(false)
const attemptsRemaining = ref<number | null>(null)

onMounted(() => {
  // Check if redirected due to expired session
  if (route.query.expired === '1') {
    sessionExpired.value = true
  }
})

async function handleLogin() {
  loading.value = true
  error.value = ''
  attemptsRemaining.value = null

  try {
    const result = await authStore.login(username.value, password.value)

    if (result.success) {
      router.push('/')
    } else {
      error.value = result.message || 'Login failed'
      if (result.attemptsRemaining !== undefined) {
        attemptsRemaining.value = result.attemptsRemaining
      }
    }
  } catch (err: unknown) {
    const errorMessage = err instanceof Error ? err.message : 'An unknown error occurred'
    error.value = errorMessage
  } finally {
    loading.value = false
  }
}
</script>
