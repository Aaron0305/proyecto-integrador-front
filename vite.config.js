import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    allowedHosts: [
      'cakes-flour-expiration-rfc.trycloudflare.com',
      'localhost',
      '127.0.0.1'
    ],
    // Configuración para manejar rutas de React Router
    // Esto evita el error 404 al recargar la página
    historyApiFallback: true
  }
})
