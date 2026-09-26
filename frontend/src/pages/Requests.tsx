import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../services/api'
import type { PipelineEvent, RequestSummary } from '../types'
import { EmptyState, ErrorState, Loading } from '../components/StateViews'
import { StatusBadge } from '../components/StatusBadge'
import { useAuth } from '../hooks/useAuth'

const PIPELINE_STAGES = [
  'REQUEST_RECEIVED',
  'INPUT_SECURITY',
  'RISK',
  'POLICY',
  'RETRIEVAL',
  'CONTEXT_SECURITY',
  'LLM',
  'OUTPUT_SECURITY',
  'FINAL_DECISION',
] as const

// Map granular stage events onto the 10 display rows (spec §33).
function stageProgress(events: PipelineEvent[]): Map<string, { state: string; ms?: number }> {
  const map = new Map<string, { state: string; ms?: number }>()
  for (const e of events) {
    const s = e.stage
    if (s === 'STAGE_FAILED') continue
    let row: string | null = null
    if (s === 'REQUEST_RECEIVED') row = 'REQUEST_RECEIVED'
    else if (s === 'INPUT_SECURITY_STARTED' || s === 'INPUT_SECURITY_COMPLETED') row = 'INPUT_SECURITY'
    else if (s === 'RISK_CALCULATED') row = 'RISK'
    else if (s === 'POLICY_EVALUATED') row = 'POLICY'
    else if (s === 'RETRIEVAL_STARTED' || s === 'RETRIEVAL_COMPLETED') row = 'RETRIEVAL'
    else if (s === 'CONTEXT_SECURITY_STARTED' || s === 'CONTEXT_SECURITY_COMPLETED') row = 'CONTEXT_SECURITY'
    else if (s === 'LLM_STARTED' || s === 'LLM_COMPLETED') row = 'LLM'
    else if (s === 'OUTPUT_SECURITY_STARTED' || s === 'OUTPUT_SECURITY_COMPLETED') row = 'OUTPUT_SECURITY'
    else if (s === 'FINAL_DECISION' || s === 'RESPONSE_SENT') row = 'FINAL_DECISION'
    if (!row) continue
    const done = s.endsWith('COMPLETED') || s === 'REQUEST_RECEIVED' || s === 'FINAL_DECISION'
    const prev = map.get(row)
    const state = done ? 'done' : 'running'
    if (!prev || state === 'done') {
      map.set(row, { state, ms: e.duration_ms })
    }
  }
  return map
}

export function Requests() {
  const { user } = useAuth()
  const [requests, setRequests] = useState<RequestSummary[] | null>(null)
  const [error, setError] = useState<Error | null>(null)
  const [liveEvents, setLiveEvents] = useState<PipelineEvent[]>([])
  const [connected, setConnected] = useState(false)
  const esRef = useRef<EventSource | null>(null)

  useEffect(() => {
    const load = () =>
      api
        .get<RequestSummary[]>('/requests?limit=50')
        .then(setRequests)
        .catch(setError)
    load()
    const timer = setInterval(load, 5000)
    return () => clearInterval(timer)
  }, [user])

  // SSE live pipeline; the UI falls back to polling the request list (above).
  useEffect(() => {
    const es = new EventSource('/api/v1/stream')
    esRef.current = es
    es.onopen = () => setConnected(true)
    es.onmessage = (msg) => {
      try {
        const event = JSON.parse(msg.data) as PipelineEvent
        setLiveEvents((prev) => [...prev.slice(-200), event])
      } catch {
        /* ignore malformed frames */
      }
    }
    es.onerror = () => setConnected(false)
    return () => {
      es.close()
      esRef.current = null
    }
  }, [])

  const latestRequestId = liveEvents.length > 0 ? liveEvents[liveEvents.length - 1].request_id : null
  const progress = stageProgress(
    liveEvents.filter((e) => e.request_id === latestRequestId),
  )

  return (
    <div>
      <div className="page-header">
        <h2>Live Requests</h2>
        <span className={`sse-badge ${connected ? 'on' : 'off'}`}>
          {connected ? '● live' : '○ polling fallback'}
        </span>
      </div>

      <section className="panel">
        <h3>Pipeline {latestRequestId ? `— ${latestRequestId.slice(0, 12)}…` : ''}</h3>
        {latestRequestId == null ? (
          <EmptyState message="Submit a chat request to see the live pipeline" />
        ) : (
          <div className="pipeline">
            {PIPELINE_STAGES.map((stage) => {
              const p = progress.get(stage)
              return (
                <div key={stage} className={`pipeline-row ${p?.state ?? 'pending'}`}>
                  <span className="pipeline-marker">{p?.state === 'done' ? '✓' : p?.state === 'running' ? '●' : '○'}</span>
                  <span className="pipeline-name">{stage}</span>
                  <span className="pipeline-ms">{p?.ms != null ? `${p.ms.toFixed(1)} ms` : p?.state === 'running' ? 'running' : 'pending'}</span>
                </div>
              )
            })}
          </div>
        )}
      </section>

      <section className="panel">
        <h3>Recent Requests</h3>
        {error ? <ErrorState error={error} /> : requests == null ? (
          <Loading />
        ) : requests.length === 0 ? (
          <EmptyState message="No requests recorded yet" />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Request</th>
                <th>Decision</th>
                <th>Risk</th>
                <th>Level</th>
                <th>Latency</th>
                <th>Policy v</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {requests.map((r) => (
                <tr key={r.request_id}>
                  <td>
                    <Link to={`/requests/${r.request_id}`} className="mono">
                      {r.request_id.slice(0, 12)}…
                    </Link>
                  </td>
                  <td><StatusBadge value={r.final_decision ?? r.status} /></td>
                  <td>{r.risk_score.toFixed(2)}</td>
                  <td><StatusBadge value={r.risk_level} /></td>
                  <td>{r.total_latency_ms != null ? `${Math.round(r.total_latency_ms)} ms` : '—'}</td>
                  <td>{r.policy_version ?? '—'}</td>
                  <td>{new Date(r.created_at).toLocaleTimeString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  )
}
