import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: ["class"],
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        evi: {
          canvas: "#0b1120",
          panel: "#111827",
          elevated: "#1f2937",
          border: "#243044",
          text: "#e5edf8",
          muted: "#94a3b8",
          accent: "#22d3ee",
          benign: "#38bdf8",
          suspicious: "#f59e0b",
          malicious: "#ef4444",
          verified: "#22c55e",
          failed: "#f43f5e",
          simulation: "#a78bfa",
        },
      },
      fontFamily: {
        sans: ["Inter", "IBM Plex Sans", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      boxShadow: {
        panel: "0 10px 30px -10px rgba(0, 0, 0, 0.5)",
      },
    },
  },
  plugins: [],
};
export default config;
