<template>
  <v-app-bar elevation="0" class="luxury-header" height="64">
    <div class="d-flex align-center ml-4">
      <!-- Menu Button -->
      <v-menu>
        <template v-slot:activator="{ props }">
          <v-btn icon variant="text" size="small" class="mr-2" v-bind="props">
            <v-icon>mdi-menu</v-icon>
          </v-btn>
        </template>
        
        <v-list>
          <v-list-item :to="{ name: 'dashboard' }">
            <template v-slot:prepend>
              <v-icon>mdi-view-dashboard</v-icon>
            </template>
            <v-list-item-title>Dashboard</v-list-item-title>
          </v-list-item>
          
          <v-list-item :to="{ name: 'all-logs' }">
            <template v-slot:prepend>
              <v-icon>mdi-shield-alert</v-icon>
            </template>
            <v-list-item-title>Threat Feed</v-list-item-title>
          </v-list-item>
          
          <v-divider />
          
          <v-list-item @click="authStore.logout">
            <template v-slot:prepend>
              <v-icon>mdi-logout</v-icon>
            </template>
            <v-list-item-title>Logout</v-list-item-title>
          </v-list-item>
        </v-list>
      </v-menu>
      
      <v-icon icon="mdi-shield-check" class="logo-icon mr-3" size="36" />
      <div class="header-branding">
        <div class="header-title">WEB CAPTURE INTELLIGENCE</div>
        <div class="header-subtitle">Threat Detection Dashboard</div>
      </div>
    </div>

    <v-spacer />

    <div class="header-actions mr-4">
      <v-btn icon variant="text" size="small" class="header-btn">
        <v-icon>mdi-bell-outline</v-icon>
        <v-badge color="error" content="3" floating />
      </v-btn>

      <v-btn icon variant="text" size="small" class="header-btn">
        <v-icon>mdi-cog-outline</v-icon>
      </v-btn>

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
import { useThemeStore } from '@/stores/theme'
import { useAuthStore } from '@/stores/auth'

const themeStore = useThemeStore()
const authStore = useAuthStore()
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
