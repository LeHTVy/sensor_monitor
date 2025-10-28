import { createRouter, createWebHistory } from 'vue-router'
import Login from '../views/Login.vue'
import Dashboard from '../views/Dashboard.vue'

const routes = [
  {
    path: '/',
    name: 'Dashboard',
    component: Dashboard,
    meta: { requiresAuth: true }
  },
  {
    path: '/login',
    name: 'Login',
    component: Login
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

router.beforeEach((to, from, next) => {
  const apiKey = localStorage.getItem('capture_api_key')
  const isAuthenticated = !!apiKey

  if (to.meta.requiresAuth && !isAuthenticated) {
    return next('/login')
  }
  if (to.name === 'Login' && isAuthenticated) {
    return next('/')
  }
  return next()
})

export default router
