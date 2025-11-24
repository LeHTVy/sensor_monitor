import { defineStore } from 'pinia'
import { ref, watch } from 'vue'

export const useThemeStore = defineStore('theme', () => {
    const isDark = ref(true) // Default to dark mode (Stealth Luxury)

    function toggleTheme() {
        isDark.value = !isDark.value
        applyTheme()
    }

    function applyTheme() {
        document.documentElement.setAttribute(
            'data-theme',
            isDark.value ? 'dark' : 'light'
        )
        localStorage.setItem('theme', isDark.value ? 'dark' : 'light')
    }

    function initTheme() {
        const saved = localStorage.getItem('theme')
        isDark.value = saved ? saved === 'dark' : true
        applyTheme()
    }

    // Auto-apply theme on load
    initTheme()

    return {
        isDark,
        toggleTheme,
        initTheme
    }
})
