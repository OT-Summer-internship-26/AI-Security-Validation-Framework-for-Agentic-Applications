import { useState, useEffect, useRef } from 'react'
import { motion } from 'framer-motion'
import type { ReactNode } from 'react'

function useCountUp(target: number, duration = 1500) {
  const [val, setVal] = useState(0)
  const started = useRef(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting && !started.current) {
        started.current = true
        const start = performance.now()
        const tick = (now: number) => {
          const p = Math.min((now - start) / duration, 1)
          const eased = 1 - Math.pow(1 - p, 3)
          setVal(target * eased)
          if (p < 1) requestAnimationFrame(tick)
          else setVal(target)
        }
        requestAnimationFrame(tick)
      }
    }, { threshold: 0.1 })
    if (ref.current) observer.observe(ref.current)
    return () => observer.disconnect()
  }, [target, duration])

  return { val, ref }
}

export function KpiCard({
  label,
  value,
  decimals = 0,
  suffix = '',
  prefix = '',
  icon,
  accentColor = '#ED1C24',
  sublabel,
}: {
  label: string
  value: number
  decimals?: number
  suffix?: string
  prefix?: string
  icon?: ReactNode
  accentColor?: string
  sublabel?: string
}) {
  const { val, ref } = useCountUp(value)

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ type: 'spring', stiffness: 300, damping: 25 }}
      whileHover={{ y: -2 }}
      className="relative overflow-hidden card p-5 shadow-card"
    >
      <div
        className="absolute top-0 left-0 w-full h-1"
        style={{ background: `linear-gradient(90deg, ${accentColor}, transparent)` }}
      />
      <div className="flex items-start justify-between mb-3">
        <span className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
          {label}
        </span>
        {icon && (
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center"
            style={{ backgroundColor: `${accentColor}15`, color: accentColor }}
          >
            {icon}
          </div>
        )}
      </div>
      <div className="text-3xl font-bold font-mono tabular-nums" style={{ color: accentColor }}>
        {prefix}{val.toFixed(decimals)}{suffix}
      </div>
      {sublabel && (
        <div className="text-xs text-text-muted mt-1.5">{sublabel}</div>
      )}
    </motion.div>
  )
}
