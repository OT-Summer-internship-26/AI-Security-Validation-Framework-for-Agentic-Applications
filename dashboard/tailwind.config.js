/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Rouge Ooredoo — RÉSERVÉ au chrome de l'app (logo, nav active, marque).
        // Ne jamais l'utiliser pour une sévérité : voir `severity.*`.
        brand: {
          DEFAULT: '#ED1C24',
          dark: '#C4161C',
          light: '#FF5A60',
        },
        // Surfaces / textes / bordures : pilotés par variables CSS → light + dark.
        bg: {
          deep: 'var(--bg-deep)',
          surface: 'var(--bg-surface)',
          elevated: 'var(--bg-elevated)',
          overlay: 'var(--bg-overlay)',
        },
        border: {
          DEFAULT: 'var(--border-base)',
          subtle: 'var(--border-subtle)',
          bright: 'var(--border-bright)',
        },
        text: {
          primary: 'var(--text-primary)',
          secondary: 'var(--text-secondary)',
          muted: 'var(--text-muted)',
        },
        // Sévérités : magenta pour Critical afin de ne PAS se confondre avec
        // le rouge de marque. Valeurs adaptées par thème via variables CSS.
        severity: {
          critical: 'var(--sev-critical)',
          high: 'var(--sev-high)',
          medium: 'var(--sev-medium)',
          low: 'var(--sev-low)',
          info: 'var(--sev-info)',
        },
        layer: {
          behavioral: 'var(--layer-behavioral)',
          static: 'var(--layer-static)',
          dynamic: 'var(--layer-dynamic)',
        },
        risk: {
          critique: 'var(--sev-critical)',
          eleve: 'var(--sev-high)',
          moyen: 'var(--sev-medium)',
          faible: 'var(--sev-low)',
          secure: 'var(--sev-info)',
        },
        focus: 'var(--focus-ring)',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
      },
      borderRadius: {
        DEFAULT: '12px',
        lg: '16px',
        xl: '20px',
      },
      boxShadow: {
        card: 'var(--shadow-card)',
        lifted: 'var(--shadow-lifted)',
        glow: '0 0 24px rgba(237,28,36,0.22)',
        'glow-blue': '0 0 24px rgba(37,99,235,0.28)',
        'glow-green': '0 0 24px rgba(4,120,87,0.25)',
      },
      keyframes: {
        'scan-sweep': {
          '0%': { transform: 'translateY(-110%)', opacity: '0' },
          '12%': { opacity: '1' },
          '88%': { opacity: '1' },
          '100%': { transform: 'translateY(110%)', opacity: '0' },
        },
        'scan-sweep-x': {
          '0%': { transform: 'translateX(-120%)' },
          '100%': { transform: 'translateX(320%)' },
        },
        'pulse-ring': {
          '0%': { boxShadow: '0 0 0 0 var(--ring-color)' },
          '70%': { boxShadow: '0 0 0 10px transparent' },
          '100%': { boxShadow: '0 0 0 0 transparent' },
        },
        'flow-dash': {
          to: { strokeDashoffset: '-24' },
        },
        'count-in': {
          '0%': { opacity: '0', transform: 'translateY(6px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        shimmer: {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
      },
      animation: {
        'scan-sweep': 'scan-sweep 2.2s ease-in-out infinite',
        'scan-sweep-x': 'scan-sweep-x 1.6s linear infinite',
        'pulse-ring': 'pulse-ring 1.8s cubic-bezier(0.4,0,0.6,1) infinite',
        'flow-dash': 'flow-dash 0.7s linear infinite',
        'count-in': 'count-in 0.4s ease-out',
        shimmer: 'shimmer 1.8s linear infinite',
      },
    },
  },
  plugins: [],
}
