import { defineConfig, loadEnv } from 'vite';

// Dev server proxies /api -> backend. The running backend serves /incidents and /health
// without an /api prefix, so the p
// proxy strips it.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  return {
    server: {
      port: 5173,
      proxy: {
        '/api': {
          target: env.VITE_BACKEND_URL || 'http://127.0.0.1:8000',
          changeOrigin: true,
          rewrite: (p) => p.replace(/^\/api/, ''),
        },
      },
    },
  };
});