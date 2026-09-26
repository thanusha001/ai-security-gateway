import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { api } from '../services/api'
import type { HealthInfo } from '../types'

interface HealthContextValue {
  health: HealthInfo | null
}

const HealthContext = createContext<HealthContextValue>({ health: null })

/** Polls /health every 15s and shares the result app-wide (topbar pill). */
export function HealthProvider({ children }: { children: ReactNode }) {
  const [health, setHealth] = useState<HealthInfo | null>(null)

  useEffect(() => {
    let cancelled = false
    const load = () => {
      if (!localStorage.getItem('gateway_token')) return
      api
        .get<HealthInfo>('/health')
        .then((h) => {
          if (!cancelled) setHealth(h)
        })
        .catch(() => {
          /* topbar pill is non-critical; keep last known state */
        })
    }
    load()
    const timer = setInterval(load, 15000)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [])

  return <HealthContext.Provider value={{ health }}>{children}</HealthContext.Provider>
}

export function useHealth() {
  return useContext(HealthContext)
}
