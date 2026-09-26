import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, ApiError } from '../services/api'
import type { SecurityEvent, Threat } from '../types'
import { EmptyState, ErrorState, Loading } from '../components/StateViews'
import { StatusBadge } from '../components/StatusBadge'

export function SecurityEventsPage() {
  const [events, setEvents] = useState<SecurityEvent[] | null>(null)
  const [error, setError] = useState<ApiError | Error | null>(null)
  const [severity, setSeverity] = useState('')
  const [detector, setDetector] = useState('')

  useEffect(() => {
    const params = new URLSearchParams({ limit: '200' })
    if (severity) params.set('severity', severity)
    if (detector) params.set('detector', detector)
    api
      .get<SecurityEvent[]>(`/events?${params}`)
      .then(setEvents)
      .catch(setError)
  }, [severity, detector])

  if (error) return <ErrorState error={error} />
  if (!events) return <Loading />

  return (
    <div>
      <div className="page-header">
        <div>
          <span className="kicker">Security</span>
          <h2>Security Events</h2>
        </div>
        <div className="filters">
          <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity filter">
            <option value="">All severities</option>
            {['low', 'medium', 'high', 'critical'].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <input
            placeholder="Filter by detector…"
            value={detector}
            onChange={(e) => setDetector(e.target.value)}
            aria-label="Detector filter"
          />
        </div>
      </div>

      {events.length === 0 ? (
        <EmptyState message="No security events match the filter" />
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>When</th>
              <th>Request</th>
              <th>Stage</th>
              <th>Detector</th>
              <th>Severity</th>
              <th>Risk</th>
              <th>Action</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e, i) => (
              <tr key={e.id ?? i}>
                <td style={{ whiteSpace: 'nowrap' }}>{e.created_at ? new Date(e.created_at).toLocaleString() : '—'}</td>
                <td>
                  <Link to={`/requests/${e.request_id}`} className="mono">
                    {e.request_id.slice(0, 10)}…
                  </Link>
                </td>
                <td className="mono">{e.stage}</td>
                <td>{e.detector ?? '—'}</td>
                <td>{e.severity ? <StatusBadge value={e.severity} /> : '—'}</td>
                <td style={{ fontVariantNumeric: 'tabular-nums' }}>{e.risk_score?.toFixed(2) ?? '—'}</td>
                <td>{e.action ? <StatusBadge value={e.action} /> : '—'}</td>
                <td className="reason-cell" title={e.reason ?? ''}>{e.reason ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

export function ThreatsPage() {
  const [threats, setThreats] = useState<Threat[] | null>(null)
  const [error, setError] = useState<ApiError | Error | null>(null)

  useEffect(() => {
    api
      .get<Threat[]>('/threats?limit=200')
      .then(setThreats)
      .catch(setError)
  }, [])

  if (error) return <ErrorState error={error} />
  if (!threats) return <Loading />
  if (threats.length === 0) return <EmptyState message="No threats detected yet" />

  return (
    <div>
      <div className="page-header">
        <div>
          <span className="kicker">Security</span>
          <h2>Threat Detections</h2>
          <p className="page-sub">Correlated detections raised by the security pipeline.</p>
        </div>
      </div>
      <table className="table">
        <thead>
          <tr>
            <th>When</th>
            <th>Request</th>
            <th>Type</th>
            <th>Detector</th>
            <th>Severity</th>
            <th>Confidence</th>
            <th>Risk</th>
            <th>Evidence</th>
          </tr>
        </thead>
        <tbody>
          {threats.map((t, i) => (
            <tr key={i}>
              <td style={{ whiteSpace: 'nowrap' }}>{t.created_at ? new Date(t.created_at).toLocaleString() : '—'}</td>
              <td>
                <Link to={`/requests/${t.request_id}`} className="mono">
                  {t.request_id.slice(0, 10)}…
                </Link>
              </td>
              <td style={{ fontWeight: 600 }}>{t.threat_type}</td>
              <td>{t.detector}</td>
              <td><StatusBadge value={t.severity} /></td>
              <td style={{ fontVariantNumeric: 'tabular-nums' }}>{t.confidence.toFixed(2)}</td>
              <td style={{ fontVariantNumeric: 'tabular-nums' }}>{t.risk_score.toFixed(2)}</td>
              <td className="mono reason-cell" title={Array.isArray(t.evidence?.evidence) ? (t.evidence!.evidence as string[]).join('; ') : ''}>
                {Array.isArray(t.evidence?.evidence) ? (t.evidence!.evidence as string[]).join('; ') : '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
