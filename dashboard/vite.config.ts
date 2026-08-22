import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  // Assets statiques du dashboard (logo Ooredoo, favicon) — dossier LOCAL.
  publicDir: path.resolve(__dirname, './public'),
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
})
