import { createRouter, createWebHistory } from 'vue-router'
import { useStore } from 'vuex'
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
  const store = useStore()
  
  if (to.meta.requiresAuth && !store.state.isAuthenticated) {
    next('/login')
  } else if (to.name === 'Login' && store.state.isAuthenticated) {
    next('/')
  } else {
    next()
  }
})

export default router
