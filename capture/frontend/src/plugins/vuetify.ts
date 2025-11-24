import 'vuetify/styles'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { aliases, mdi } from 'vuetify/iconsets/mdi'
import '@mdi/font/css/materialdesignicons.css'

const darkTheme = {
  dark: true,
  colors: {
    background: '#0a0a0a',
    surface: '#1a1a1a',
    'surface-variant': '#141414',
    primary: '#D4AF37', // Gold
    'primary-darken-1': '#B8941F',
    secondary: '#F4E4C1',
    accent: '#D4AF37',
    error: '#EF4444',
    info: '#3B82F6',
    success: '#10B981',
    warning: '#F59E0B',
    'on-background': '#FFFFFF',
    'on-surface': '#FFFFFF',
    'on-primary': '#000000',
  }
}

const lightTheme = {
  dark: false,
  colors: {
    background: '#F5F5F5',
    surface: '#FFFFFF',
    'surface-variant': '#FEFEFE',
    primary: '#C9A961', // Beige
    'primary-darken-1': '#B39551',
    secondary: '#E8D7B8',
    accent: '#C9A961',
    error: '#EF4444',
    info: '#3B82F6',
    success: '#10B981',
    warning: '#F59E0B',
    'on-background': '#000000', // Black text
    'on-surface': '#000000',     // Black text
    'on-primary': '#FFFFFF',
  }
}

export default createVuetify({
  components,
  directives,
  icons: {
    defaultSet: 'mdi',
    aliases,
    sets: {
      mdi,
    },
  },
  theme: {
    defaultTheme: 'dark',
    themes: {
      dark: darkTheme,
      light: lightTheme,
    },
    variations: {
      colors: ['primary', 'secondary'],
      lighten: 2,
      darken: 2,
    }
  }
})
