import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts'
import { api, ApiError } from '../services/api'
import type { HealthInfo, Metrics } from '../types'
import { ErrorState, Loading } from '../components/StateViews'
import { StatusBadge } from '../components/StatusBadge'

export function Dashboard() {
  const [metrics, setMetrics] = useState<Metrics | null>(null)
  const [health, setHealth] = useState<HealthInfo | null>(null)
  const [error, setError] = useState<ApiError | Error | null>(null)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const [m, h] = await Promise.all([api.get<Metrics>('/metrics'), api.get<HealthInfo>('/health')])
        if (!cancelled) {
          setMetrics(m)
          setHealth(h)
          setError(null)
        }
      } catch (e) {
        if (!cancelled) setError(e as ApiError)
      }
    }
    load()
    const timer = setInterval(load, 10000)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [])

  if (error) return <ErrorState error={error} />
  if (!metrics || !health) return <Loading label="Loading metrics…" />

  const decisionData = [
    { name: 'Allowed', value: metrics.allowed_requests, color: '#16a34a' },
    { name: 'Blocked', value: metrics.blocked_requests, color: '#dc2626' },
    { name: 'Redacted', value: metrics.redacted_requests, color: '#d97706' },
    { name: 'Escalated', value: metrics.escalated_requests, color: '#7c3aed' },
  ].filter((d) => d.value > 0)

  const detectorData = Object.entries(metrics.detector_counts).map(([name, count]) => ({
    name,
    count,
  }))

  return (
    <div>
      <div className="page-header">
        <h2>Security Dashboard</h2>
        <StatusBadge value={health.status} />
      </div>

      <div className="cards">
        <Card label="Total Requests" value={metrics.total_requests} />
        <Card label="Allowed" value={metrics.allowed_requests} tone="ok" />
        <Card label="Blocked" value={metrics.blocked_requests} tone="bad" />
        <Card label="Redacted" value={metrics.redacted_requests} tone="warn" />
        <Card label="Threats Detected" value={metrics.threat_count} tone="bad" />
        <Card label="Avg Risk Score" value={metrics.average_risk_score?.toFixed(2) ?? '—'} />
        <Card
          label="Avg Latency"
          value={metrics.average_latency_ms != null ? `${Math.round(metrics.average_latency_ms)} ms` : '—'}
        />
        <Card
          label="P95 Latency"
          value={metrics.p95_latency_ms != null ? `${Math.round(metrics.p95_latency_ms)} ms` : '—'}
        />
        <Card label="LLM Requests" value={metrics.llm_requests} />
        <Card label="Total Tokens" value={metrics.total_tokens ?? '—'} />
      </div>

      <div className="panels">
        <section className="panel">
          <h3>Final Decisions</h3>
          {decisionData.length === 0 ? (
            <p className="state-empty">No requests yet</p>
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <Pie data={decisionData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85}>
                  {decisionData.map((d) => (
                    <Cell key={d.name} fill={d.color} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          )}
        </section>

        <section className="panel">
          <h3>Threats by Detector</h3>
          {detectorData.length === 0 ? (
            <p className="state-empty">No threats detected</p>
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={detectorData}>
                <XAxis dataKey="name" angle={-25} textAnchor="end" height={60} />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count" fill="#dc2626" />
              </BarChart>
            </ResponsiveContainer>
          )}
        </section>
      </div>

      <section className="panel">
        <h3>Component Health</h3>
        <div className="health-grid">
          {Object.entries(health.components).map(([name, status]) => (
            <div key={name} className="health-item">
              <span>{name}</span>
              <StatusBadge value={status} />
            </div>
          ))}
        </div>
        <p className="muted">
          Full detail on the <Link to="/health">System Health</Link> page.
        </p>
      </section>
    </div>
  )
}

function Card({ label, value, tone }: { label: string; value: string | number; tone?: 'ok' | 'bad' | 'warn' }) {
  return (
    <div className={`card card-${tone ?? 'neutral'}`}>
      <div className="card-value">{value}</div>
      <div className="card-label">{label}</div>
    </div>
  )
}
