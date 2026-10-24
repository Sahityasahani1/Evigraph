import { defineConfig, loadEnv } from 'vite';

// Dev server proxies /api -> backend. Backend routes already start with /api, so no rewrite.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  return {
    server: {
      port: 5173,
      proxy: { '/api': { target: env.VITE_BACKEND_URL || 'http://localhost:8000', changeOrigin: true } },
    },
  };
});
