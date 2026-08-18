/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#07121f',
        panel: '#0e1c2f',
        accent: '#00d4a6',
        warn: '#ffb020',
        danger: '#ff4d6d',
      },
    },
  },
  plugins: [],
};
