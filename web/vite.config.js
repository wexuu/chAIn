import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The SPA is mounted by FastAPI under the "/app" path (StaticFiles, html=True).
// `base: './'` makes the built index.html reference its assets relatively, so it
// works under /app/ without knowing the mount path at build time.
// NOTE: API calls in the app itself use ROOT-ABSOLUTE paths (e.g. "/targets/list")
// because the API lives at the server root, not under /app.
export default defineConfig({
  base: './',
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
})
