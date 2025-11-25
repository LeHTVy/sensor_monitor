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
    primary: '#021273',           // Royal blue text color
    'primary-darken-1': '#020b48ff',
    secondary: '#E8D7B8',
    accent: '#021273',
    error: '#EF4444',
    info: '#3B82F6',
    success: '#10B981',
    warning: '#F59E0B',
    'on-background': '#021273',   // Royal blue text
    'on-surface': '#021273',       // Royal blue text
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
