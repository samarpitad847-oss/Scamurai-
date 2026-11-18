import { defineConfig } from 'vite';

export default defineConfig({
  // Vanilla HTML, CSS and JavaScript frontend.
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
    },
  },
});
