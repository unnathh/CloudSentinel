/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#020617',     // Deep slate-950 background
          card: '#0b0f19',   // Very dark navy card
          cardLight: '#111827', // Dark gray card fallback
          border: '#1e293b', // slate-800
          text: '#f8fafc',   // slate-50
          muted: '#64748b',  // slate-500
          critical: '#f43f5e', // Rose-500 for critical findings
          high: '#f97316',     // Orange-500 for high findings
          medium: '#eab308',   // Yellow-500 for medium findings
          low: '#3b82f6',      // Blue-500 for low findings
          info: '#06b6d4',     // Cyan-500 for info
          success: '#10b981',  // Emerald-500 for compliance/safe
        }
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      }
    },
  },
  plugins: [],
}
