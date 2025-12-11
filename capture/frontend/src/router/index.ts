import { createRouter, createWebHistory } from 'vue-router'
import LoginView from '@/views/LoginView.vue'
import DashboardView from '@/views/DashboardView.vue'
import AllLogsView from '@/views/AllLogsView.vue'
import DataExplorerView from '@/views/DataExplorerView.vue'
import { useAuthStore } from '../stores/auth'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: LoginView
    },
    {
      path: '/',
      name: 'dashboard',
      component: DashboardView,
      meta: { requiresAuth: true }
    },
    {
      path: '/logs',
      name: 'all-logs',
      component: AllLogsView,
      meta: { requiresAuth: true }
    },
    {
      path: '/explorer',
      name: 'data-explorer',
      component: DataExplorerView,
      meta: { requiresAuth: true }
    },
    {
      path: '/attackers',
      name: 'attackers',
      component: () => import('@/views/AttackersView.vue'),
      meta: { requiresAuth: true }
    }
  ]
})

router.beforeEach((to, from, next) => {
  const authStore = useAuthStore()

  if (to.meta.requiresAuth) {
    if (!authStore.isLoggedIn) {
      next('/login')
    } else if (authStore.isTokenExpired()) {
      // Token expired - logout and redirect with message
      authStore.logout()
      next({ path: '/login', query: { expired: '1' } })
    } else {
      next()
    }
  } else if (to.path === '/login' && authStore.isLoggedIn && !authStore.isTokenExpired()) {
    next('/')
  } else {
    next()
  }
})

export default router
