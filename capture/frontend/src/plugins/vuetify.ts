import 'vuetify/styles'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { aliases, mdi } from 'vuetify/iconsets/mdi'
import '@mdi/font/css/materialdesignicons.css'

const darkTheme = {
  dark: true,
  colors: {
    background: '#000000',        // Black background
    surface: '#1a1a1a',
    'surface-variant': '#141414',
    primary: '#d5ba76',           // Golden
    'primary-darken-1': '#B8941F',
    secondary: '#F4E4C1',
    accent: '#d5ba76',
    error: '#EF4444',
    info: '#3B82F6',
    success: '#10B981',
    warning: '#F59E0B',
    'on-background': '#d5ba76',   // Golden text
    'on-surface': '#d5ba76',       // Golden text
    'on-primary': '#000000',
  }
}

const lightTheme = {
  dark: false,
  colors: {
    background: '#FFFFFF',        // White background
    surface: '#F5F5F5',
    'surface-variant': '#FEFEFE',
    primary: '#9e8662',           // Brown/beige text color
    'primary-darken-1': '#8B7456',
    secondary: '#E8D7B8',
    accent: '#9e8662',
    error: '#EF4444',
    info: '#3B82F6',
    success: '#10B981',
    warning: '#F59E0B',
    'on-background': '#9e8662',   // Brown text
    'on-surface': '#9e8662',       // Brown text
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
