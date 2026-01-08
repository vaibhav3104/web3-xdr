/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'neon-green': '#00ff00',
        'neon-red': '#ff0000',
        'neon-yellow': '#ffff00',
        'dark-bg': '#000000',
      },
      fontFamily: {
        'mono': ['Courier New', 'Monaco', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(0, 255, 0, 0.5)' },
          '100%': { boxShadow: '0 0 20px rgba(0, 255, 0, 1)' },
        },
      },
    },
  },
  plugins: [],
}

