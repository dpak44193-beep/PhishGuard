/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        soc: {
          bg:         '#0d1117',
          surface:    '#161b22',
          border:     '#21262d',
          text:       '#c9d1d9',
          muted:      '#8b949e',
          accent:     '#58a6ff',
          safe:       '#3fb950',
          suspicious: '#d29922',
          malicious:  '#f85149',
        },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'ui-monospace', 'monospace'],
      },
    },
  },
  plugins: [],
}
