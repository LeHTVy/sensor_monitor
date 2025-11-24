import { defineStore } from 'pinia'
import { ref } from 'vue'
import { useTheme } from 'vuetify'

export const useThemeStore = defineStore('theme', () => {
    const isDark = ref(true) // Default to dark mode
    let vuetifyTheme: ReturnType<typeof useTheme> | null = null

    function setVuetifyTheme(theme: ReturnType<typeof useTheme>) {
        vuetifyTheme = theme
    }

    function toggleTheme() {
        isDark.value = !isDark.value
        if (vuetifyTheme) {
            vuetifyTheme.global.name.value = isDark.value ? 'dark' : 'light'
        }
        localStorage.setItem('theme', isDark.value ? 'dark' : 'light')
    }

    function initTheme() {
        const saved = localStorage.getItem('theme')
        isDark.value = saved ? saved === 'dark' : true
        if (vuetifyTheme) {
            vuetifyTheme.global.name.value = isDark.value ? 'dark' : 'light'
        }
    }

    return {
        isDark,
        toggleTheme,
        initTheme,
        setVuetifyTheme
    }
})
