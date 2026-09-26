import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts'
import { api, ApiError } from '../services/api'
import type { HealthInfo, Metrics } from '../types'
import { ErrorState, Loading } from '../components/StateViews'
import { StatusBadge } from '../components/StatusBadge'

const DECISION_COLORS = ['#34d399', '#f87171', '#fbbf24', '#a78bfa']
const GRID = '#1b2740'
const AXIS = '#5d6b83'

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
    { name: 'Allowed', value: metrics.allowed_requests, color: DECISION_COLORS[0] },
    { name: 'Blocked', value: metrics.blocked_requests, color: DECISION_COLORS[1] },
    { name: 'Redacted', value: metrics.redacted_requests, color: DECISION_COLORS[2] },
    { name: 'Escalated', value: metrics.escalated_requests, color: DECISION_COLORS[3] },
  ].filter((d) => d.value > 0)

  const detectorData = Object.entries(metrics.detector_counts).map(([name, count]) => ({
    name,
    count,
  }))

  return (
    <div>
      <div className="page-header">
        <div>
          <span className="kicker">Overview</span>
          <h2>Security posture</h2>
          <p className="page-sub">
            Aggregated from every request that passed through the gateway pipeline.
          </p>
        </div>
        <div className="filters">
          <StatusBadge value={health.status} />
        </div>
      </div>

      <div className="cards">
        <Card label="Total Requests" value={metrics.total_requests} />
        <Card label="Allowed" value={metrics.allowed_requests} tone="ok" />
        <Card label="Blocked" value={metrics.blocked_requests} tone="bad" />
        <Card label="Redacted" value={metrics.redacted_requests} tone="warn" />
        <Card label="Threats" value={metrics.threat_count} tone="bad" />
        <Card label="Avg Risk" value={metrics.average_risk_score?.toFixed(2) ?? '—'} />
        <Card
          label="Avg Latency"
          value={metrics.average_latency_ms != null ? `${Math.round(metrics.average_latency_ms)} ms` : '—'}
        />
        <Card
          label="P95 Latency"
          value={metrics.p95_latency_ms != null ? `${Math.round(metrics.p95_latency_ms)} ms` : '—'}
        />
        <Card label="LLM Calls" value={metrics.llm_requests} />
        <Card label="Total Tokens" value={metrics.total_tokens != null ? metrics.total_tokens.toLocaleString() : '—'} />
      </div>

      <div className="panels">
        <section className="panel">
          <h3>Final decisions</h3>
          {decisionData.length === 0 ? (
            <p className="state-empty">No requests yet — send one from the Gateway Console</p>
          ) : (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie data={decisionData} dataKey="value" nameKey="name" innerRadius={58} outerRadius={88} paddingAngle={2} stroke="none">
                  {decisionData.map((d) => (
                    <Cell key={d.name} fill={d.color} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend iconType="circle" iconSize={8} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </section>

        <section className="panel">
          <h3>Threats by detector</h3>
          {detectorData.length === 0 ? (
            <p className="state-empty">No threats detected</p>
          ) : (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={detectorData} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
                <XAxis dataKey="name" angle={-22} textAnchor="end" height={58} tick={{ fill: AXIS, fontSize: 11 }} stroke={GRID} />
                <YAxis allowDecimals={false} tick={{ fill: AXIS, fontSize: 11 }} stroke={GRID} />
                <Tooltip cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
                <Bar dataKey="count" fill="#f87171" radius={[4, 4, 0, 0]} maxBarSize={42} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </section>
      </div>

      <section className="panel">
        <h3>Component health</h3>
        <div className="health-grid">
          {Object.entries(health.components).map(([name, status]) => (
            <div key={name} className="health-item">
              <span>{name}</span>
              <StatusBadge value={status} />
            </div>
          ))}
        </div>
        <p className="muted" style={{ marginBottom: 0 }}>
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
