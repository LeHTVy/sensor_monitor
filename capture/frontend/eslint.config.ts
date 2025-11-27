import { globalIgnores } from 'eslint/config'
import { defineConfigWithVueTs, vueTsConfigs } from '@vue/eslint-config-typescript'
import pluginVue from 'eslint-plugin-vue'
import pluginVitest from '@vitest/eslint-plugin'
import skipFormatting from '@vue/eslint-config-prettier/skip-formatting'

// To allow more languages other than `ts` in `.vue` files, uncomment the following lines:
// import { configureVueProject } from '@vue/eslint-config-typescript'
// configureVueProject({ scriptLangs: ['ts', 'tsx'] })
// More info at https://github.com/vuejs/eslint-config-typescript/#advanced-setup

export default defineConfigWithVueTs(
  {
    name: 'app/files-to-lint',
    files: ['**/*.{ts,mts,tsx,vue}'],
  },

  globalIgnores(['**/dist/**', '**/dist-ssr/**', '**/coverage/**']),

  pluginVue.configs['flat/essential'],
  vueTsConfigs.recommended,

  {
    ...pluginVitest.configs.recommended,
    files: ['src/**/__tests__/*'],
  },
  {
    rules: {
      'vue/valid-v-slot': 'off', // Disable v-slot validation
      '@typescript-eslint/no-unused-vars': 'off', // Disable unused vars warning
      'vue/no-unused-vars': 'off', // Disable unused vars in Vue templates
      'vue/no-unused-components': 'off', // Disable unused component warning
      'vue/no-v-html': 'off', // Disable v-html warning
      'vue/no-css-vars-in-style': 'off', // Disable CSS variable usage warning
    },
  },
  skipFormatting,
)
