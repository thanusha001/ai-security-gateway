import { useEffect, useState } from 'react'
import { api, ApiError } from '../services/api'
import type { AuditEntry, HealthInfo, LLMUsage } from '../types'
import { EmptyState, ErrorState, Loading, Unavailable } from '../components/StateViews'
import { StatusBadge } from '../components/StatusBadge'

export function LLMUsagePage() {
  const [usage, setUsage] = useState<LLMUsage | null>(null)
  const [error, setError] = useState<ApiError | Error | null>(null)

  useEffect(() => {
    api.get<LLMUsage>('/llm/usage').then(setUsage).catch(setError)
  }, [])

  if (error) return <ErrorState error={error} />
  if (!usage) return <Loading />
  if (usage.models.length === 0) return <EmptyState message="No LLM calls recorded yet" />

  return (
    <div>
      <div className="page-header">
        <h2>LLM Usage</h2>
      </div>

      <section className="panel">
        <h3>Token-count sources</h3>
        <div className="kv-grid">
          {Object.entries(usage.token_count_sources).map(([source, count]) => (
            <div key={source}>
              <StatusBadge value={source?.toUpperCase() ?? 'UNAVAILABLE'} /> {count} calls
            </div>
          ))}
        </div>
        <p className="muted">
          EXACT = provider-reported usage. ESTIMATED = heuristic (~4 chars/token) and never
          presented as exact.
        </p>
      </section>

      <table className="table">
        <thead>
          <tr>
            <th>Model</th>
            <th>Provider</th>
            <th>Requests</th>
            <th>Failures</th>
            <th>Input Tokens</th>
            <th>Output Tokens</th>
            <th>Total Tokens</th>
            <th>Avg Generation</th>
            <th>Avg Tokens/sec</th>
          </tr>
        </thead>
        <tbody>
          {usage.models.map((m) => (
            <tr key={`${m.provider}-${m.model}`}>
              <td>{m.model}</td>
              <td>{m.provider}</td>
              <td>{m.requests}</td>
              <td>{m.failures}</td>
              <td>{m.input_tokens.toLocaleString()}</td>
              <td>{m.output_tokens.toLocaleString()}</td>
              <td>{m.total_tokens.toLocaleString()}</td>
              <td>{m.avg_generation_ms != null ? `${Math.round(m.avg_generation_ms)} ms` : '—'}</td>
              <td>{m.avg_tokens_per_second?.toFixed(1) ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function AuditPage() {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null)
  const [error, setError] = useState<ApiError | Error | null>(null)
  const [action, setAction] = useState('')

  useEffect(() => {
    const params = new URLSearchParams({ limit: '200' })
    if (action) params.set('action', action)
    api.get<AuditEntry[]>(`/audit?${params}`).then(setEntries).catch(setError)
  }, [action])

  if (error) return <ErrorState error={error} />
  if (!entries) return <Loading />
  if (entries.length === 0) return <EmptyState message="No audit entries" />

  return (
    <div>
      <div className="page-header">
        <h2>Audit Logs</h2>
        <div className="filters">
          <input
            placeholder="filter by action (login, policy_activate…)"
            value={action}
            onChange={(e) => setAction(e.target.value)}
          />
        </div>
      </div>
      <table className="table">
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>User</th>
            <th>Action</th>
            <th>Resource</th>
            <th>Request</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((a) => (
            <tr key={a.id}>
              <td>{a.created_at ? new Date(a.created_at).toLocaleString() : '—'}</td>
              <td>{a.user_id ?? '—'}</td>
              <td>{a.action}</td>
              <td>{a.resource_type ? `${a.resource_type}:${a.resource_id ?? ''}` : '—'}</td>
              <td className="mono">{a.request_id ?? '—'}</td>
              <td className="reason-cell">
                {a.details ? JSON.stringify(a.details) : '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function HealthPage() {
  const [health, setHealth] = useState<HealthInfo | null>(null)
  const [error, setError] = useState<ApiError | Error | null>(null)

  useEffect(() => {
    const load = () =>
      api
        .get<HealthInfo>('/health')
        .then(setHealth)
        .catch(setError)
    load()
    const timer = setInterval(load, 10000)
    return () => clearInterval(timer)
  }, [])

  if (error) return <ErrorState error={error} />
  if (!health) return <Loading label="Checking components…" />

  return (
    <div>
      <div className="page-header">
        <h2>System Health</h2>
        <StatusBadge value={health.status} />
      </div>
      <div className="health-grid large">
        {Object.entries(health.components).map(([name, status]) => (
          <div key={name} className="health-item">
            <strong>{name}</strong>
            <StatusBadge value={status} />
          </div>
        ))}
      </div>
      {Object.values(health.components).some((s) => s !== 'healthy') && (
        <section className="panel">
          <h3>Unavailable components</h3>
          <Unavailable message="Components marked UNAVAILABLE above are not reachable. The gateway keeps enforcing input/policy security; LLM and RAG features degrade as documented in docs/security-model.md." />
        </section>
      )}
    </div>
  )
}
