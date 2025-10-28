<template>
  <v-app>
    <v-app-bar
      v-if="$store.state.isAuthenticated"
      color="primary"
      dark
      prominent
    >
      <v-app-bar-title>
        <v-icon class="mr-2">mdi-shield-search</v-icon>
        Capture Server Dashboard
      </v-app-bar-title>
      
      <v-spacer></v-spacer>
      
      <v-btn
        icon
        @click="logout"
        title="Logout"
      >
        <v-icon>mdi-logout</v-icon>
      </v-btn>
    </v-app-bar>

    <v-main>
      <router-view />
    </v-main>
  </v-app>
</template>

<script>
import { useStore } from 'vuex'

export default {
  name: 'App',
  setup() {
    const store = useStore()
    
    // Check for saved authentication on app start
    const savedApiKey = localStorage.getItem('capture_api_key')
    const savedUser = localStorage.getItem('capture_user')
    
    if (savedApiKey && savedUser) {
      store.commit('SET_AUTHENTICATED', {
        isAuthenticated: true,
        apiKey: savedApiKey,
        user: JSON.parse(savedUser)
      })
    }
    
    return {}
  },
  methods: {
    logout() {
      this.$store.dispatch('logout')
      this.$router.push('/login')
    }
  }
}
</script>
