<template>
  <v-container class="fill-height" fluid>
    <v-row align="center" justify="center">
      <v-col cols="12" sm="8" md="4">
        <v-card class="elevation-12">
          <v-toolbar color="primary" dark flat>
            <v-toolbar-title>Capture Server Login</v-toolbar-title>
          </v-toolbar>
          
          <v-card-text>
            <v-form @submit.prevent="handleLogin">
              <v-text-field
                v-model="username"
                label="Username"
                name="username"
                prepend-icon="mdi-account"
                type="text"
                required
              ></v-text-field>
              
              <v-text-field
                v-model="password"
                label="Password"
                name="password"
                prepend-icon="mdi-lock"
                type="password"
                required
              ></v-text-field>
            </v-form>
          </v-card-text>
          
          <v-card-actions>
            <v-spacer></v-spacer>
            <v-btn
              color="primary"
              @click="handleLogin"
              :loading="loading"
              :disabled="!username || !password"
            >
              Login
            </v-btn>
          </v-card-actions>
          
          <v-alert
            v-if="error"
            type="error"
            dismissible
            @input="error = null"
            class="ma-4"
          >
            {{ error }}
          </v-alert>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>

<script>
import { ref } from 'vue'
import { useStore } from 'vuex'
import { useRouter } from 'vue-router'

export default {
  name: 'Login',
  setup() {
    const store = useStore()
    const router = useRouter()
    
    const username = ref('admin')
    const password = ref('capture2024')
    const loading = ref(false)
    const error = ref(null)
    
    const handleLogin = async () => {
      loading.value = true
      error.value = null
      
      const result = await store.dispatch('login', {
        username: username.value,
        password: password.value
      })
      
      if (result.success) {
        router.push('/')
      } else {
        error.value = result.message || 'Login failed'
      }
      
      loading.value = false
    }
    
    return {
      username,
      password,
      loading,
      error,
      handleLogin
    }
  }
}
</script>
