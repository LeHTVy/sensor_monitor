<template>
  <!-- Navigation Drawer (Slide-out Sidebar) -->
  <v-navigation-drawer
    v-model="drawer"
    temporary
    location="left"
    width="280"
  >
    <v-list nav>
      <v-list-item class="py-4 px-4" :to="{ name: 'dashboard' }" style="cursor: pointer;">
        <div class="d-flex align-center">
          <v-img :src="logoSrc" width="32" height="32" class="mr-3" contain />
          <div>
            <div class="text-subtitle-1 font-weight-bold">SHADOWTRAP</div>
            <div class="text-caption">Hunt in Silence, Strike in Darkness</div>
          </div>
        </div>
      </v-list-item>

      <v-divider class="my-2" />

      <v-list-item
        :to="{ name: 'dashboard' }"
        prepend-icon="mdi-view-dashboard"
        title="Dashboard"
        value="dashboard"
      />

      <v-list-item
        :to="{ name: 'all-logs' }"
        prepend-icon="mdi-shield-alert"
        title="Threat Feed"
        value="threat-feed"
      />

      <v-list-item
        :to="{ name: 'data-explorer' }"
        prepend-icon="mdi-chart-box-outline"
        title="Data Explorer"
        value="data-explorer"
      />

      <v-list-item
        :to="{ name: 'attackers' }"
        prepend-icon="mdi-radar"
        title="Attackers"
        value="attackers"
      />

      <v-divider class="my-2" />

      <v-list-item
        @click="authStore.logout"
        prepend-icon="mdi-logout"
        title="Logout"
        value="logout"
      />
    </v-list>
  </v-navigation-drawer>

  <!-- App Bar -->
  <v-app-bar elevation="0" class="luxury-header" height="64">
    <div class="d-flex align-center ml-4">
      <!-- Menu Button - Opens Sidebar -->
      <v-btn 
        icon 
        variant="text" 
        size="small" 
        class="mr-2" 
        @click="drawer = !drawer"
      >
        <v-icon>mdi-menu</v-icon>
      </v-btn>
      
      <div class="d-flex align-center clickable-logo" @click="navigateToDashboard" style="cursor: pointer;">
        <v-img :src="logoSrc" class="logo-icon mr-3" width="36" height="36" contain />
        <div class="header-branding">
          <div class="header-title">SHADOWTRAP</div>
          <div class="header-subtitle">Hunt in Silence, Strike in Darkness</div>
        </div>
      </div>
    </div>

    <v-spacer />

    <div class="header-actions mr-4">
      <v-btn 
        icon 
        variant="text" 
        size="small" 
        class="header-btn theme-toggle"
        @click="themeStore.toggleTheme()"
      >
        <v-icon>{{ themeStore.isDark ? 'mdi-weather-sunny' : 'mdi-weather-night' }}</v-icon>
      </v-btn>

      <v-btn icon variant="text" size="small" class="header-btn" @click="authStore.logout">
        <v-icon>mdi-logout</v-icon>
      </v-btn>
    </div>
  </v-app-bar>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { useThemeStore } from '@/stores/theme'
import { useAuthStore } from '@/stores/auth'

const themeStore = useThemeStore()
const authStore = useAuthStore()
const router = useRouter()
const drawer = ref(false)

const logoSrc = computed(() => {
  return themeStore.isDark ? '/Logo-Golden.png' : '/Logo-Blue.png'
})

const navigateToDashboard = () => {
  router.push({ name: 'dashboard' })
}
</script>

<style scoped>
.luxury-header {
  background: var(--bg-secondary) !important;
  border-bottom: 1px solid var(--border-color) !important;
  backdrop-filter: blur(10px);
}

.logo-icon {
  color: var(--accent-primary) !important;
  filter: drop-shadow(0 0 8px var(--accent-primary));
}

.header-branding {
  display: flex;
  flex-direction: column;
}

.header-title {
  font-size: 14px;
  font-weight: 700;
  letter-spacing: 1.5px;
  color: var(--text-primary);
  text-transform: uppercase;
}

.header-subtitle {
  font-size: 10px;
  font-weight: 400;
  color: var(--text-secondary);
  letter-spacing: 0.5px;
}

.header-actions {
  display: flex;
  gap: 8px;
  align-items: center;
}

.header-btn {
  color: var(--text-secondary) !important;
  transition: all 0.2s ease;
}

.header-btn:hover {
  color: var(--accent-primary) !important;
  transform: translateY(-2px);
}

.theme-toggle {
  position: relative;
}

.theme-toggle::before {
  content: '';
  position: absolute;
  width: 100%;
  height: 100%;
  background: var(--accent-primary);
  border-radius: 50%;
  opacity: 0;
  transition: opacity 0.3s ease;
}

.theme-toggle:hover::before {
  opacity: 0.1;
}
</style>
