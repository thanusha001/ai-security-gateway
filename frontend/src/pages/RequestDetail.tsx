import { Fragment, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, ApiError } from '../services/api'
import type { RequestDetail } from '../types'
import { ErrorState, Loading } from '../components/StateViews'
import { StatusBadge } from '../components/StatusBadge'

export function RequestDetail() {
  const { requestId } = useParams<{ requestId: string }>()
  const [detail, setDetail] = useState<RequestDetail | null>(null)
  const [error, setError] = useState<ApiError | Error | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)

  useEffect(() => {
    if (!requestId) return
    api
      .get<RequestDetail>(`/requests/${requestId}`)
      .then(setDetail)
      .catch(setError)
  }, [requestId])

  if (error) return <ErrorState error={error} />
  if (!detail) return <Loading label="Loading request trace…" />

  const { request, events, retrievals, llm, threats } = detail

  return (
    <div>
      <div className="page-header">
        <div>
          <span className="kicker">Trace</span>
          <h2>Request Detail</h2>
        </div>
        <span className="mono chip" style={{ cursor: 'default' }}>{request.request_id}</span>
        <div className="filters">
          <Link className="btn-ghost button" to="/requests" style={{ padding: '8px 14px' }}>← All requests</Link>
        </div>
      </div>

      <div className="cards">
        <Card label="Decision" value={<StatusBadge value={request.final_decision ?? request.status} />} />
        <Card label="Risk Score" value={request.risk_score.toFixed(2)} />
        <Card label="Risk Level" value={<StatusBadge value={request.risk_level} />} />
        <Card label="Policy Version" value={request.policy_version ?? '—'} />
        <Card
          label="Total Latency"
          value={request.total_latency_ms != null ? `${Math.round(request.total_latency_ms)} ms` : '—'}
        />
        <Card label="Error Code" value={request.error_code ?? '—'} />
      </div>

      <section className="panel">
        <h3>Input / Output</h3>
        <div className="two-col">
          <div>
            <h4>Stored input</h4>
            <pre className="text-block">{request.input_text ?? '—'}</pre>
          </div>
          <div>
            <h4>Final response</h4>
            <pre className="text-block">{request.response_text ?? '[BLOCKED — no response returned]'}</pre>
          </div>
        </div>
      </section>

      <section className="panel">
        <h3>Timeline &amp; detectors</h3>
        {events.length === 0 ? (
          <p className="state-empty">No events recorded</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Stage</th>
                <th>Event</th>
                <th>Status</th>
                <th>Detector</th>
                <th>Risk</th>
                <th>Action</th>
                <th>ms</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e, i) => {
                const key = `${e.stage}-${e.event_type}-${i}`
                const isOpen = expanded === key
                return (
                  <Fragment key={key}>
                    <tr
                      className="expandable"
                      onClick={() => setExpanded(isOpen ? null : key)}
                    >
                      <td className="mono">{e.created_at ? new Date(e.created_at).toLocaleTimeString() : '—'}</td>
                      <td className="mono">{e.stage}</td>
                      <td>{e.event_type}</td>
                      <td><StatusBadge value={e.status} /></td>
                      <td>{e.detector ?? '—'}</td>
                      <td style={{ fontVariantNumeric: 'tabular-nums' }}>{e.risk_score != null ? e.risk_score.toFixed(2) : '—'}</td>
                      <td>{e.action ? <StatusBadge value={e.action} /> : '—'}</td>
                      <td style={{ fontVariantNumeric: 'tabular-nums' }}>{e.latency_ms != null ? e.latency_ms.toFixed(1) : '—'}</td>
                    </tr>
                    {isOpen && (
                      <tr>
                        <td colSpan={8} className="detail-cell">
                          <div style={{ marginBottom: 6 }}><strong>Reason:</strong> {e.reason ?? '—'}</div>
                          <div style={{ marginBottom: 6 }}>
                            <strong>Confidence:</strong> {e.confidence ?? '—'} · <strong>Detector version:</strong> {e.detector_version ?? '—'}
                          </div>
                          {e.evidence && (
                            <pre className="text-block">{JSON.stringify(e.evidence, null, 2)}</pre>
                          )}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        )}
      </section>

      <section className="panel">
        <h3>Retrieved chunks</h3>
        {retrievals.length === 0 ? (
          <p className="state-empty">No retrieval for this request (or RAG disabled)</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Document</th>
                <th>Chunk</th>
                <th>Similarity</th>
                <th>Included</th>
                <th>Status</th>
                <th>Exclusion reason</th>
              </tr>
            </thead>
            <tbody>
              {retrievals.map((r) => (
                <tr key={`${r.document_id}-${r.chunk_id}`}>
                  <td className="mono">{r.document_id.slice(0, 12)}…</td>
                  <td>#{r.chunk_id}</td>
                  <td style={{ fontVariantNumeric: 'tabular-nums' }}>{r.similarity?.toFixed(3) ?? '—'}</td>
                  <td>{r.included ? '✓' : '✗'}</td>
                  <td><StatusBadge value={r.security_status} /></td>
                  <td>{r.exclusion_reason ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="panel">
        <h3>LLM</h3>
        {llm.length === 0 ? (
          <p className="state-empty">No LLM call for this request</p>
        ) : (
          llm.map((l, i) => (
            <div key={i} className="kv-grid">
              <div><strong>Model:</strong> {l.model} ({l.provider})</div>
              <div><strong>Input tokens:</strong> {l.input_tokens ?? '—'}</div>
              <div><strong>Output tokens:</strong> {l.output_tokens ?? '—'}</div>
              <div>
                <strong>Token source:</strong>{' '}
                <StatusBadge value={(l.token_count_source ?? 'unavailable').toUpperCase()} />
              </div>
              <div><strong>Generation:</strong> {l.generation_latency_ms?.toFixed(0) ?? '—'} ms</div>
              <div><strong>Tokens/sec:</strong> {l.tokens_per_second?.toFixed(1) ?? '—'}</div>
              {l.error_code && <div><strong>Error:</strong> {l.error_code}</div>}
            </div>
          ))
        )}
      </section>

      <section className="panel">
        <h3>Threats detected</h3>
        {threats.length === 0 ? (
          <p className="state-empty">No threats for this request</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Detector</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {threats.map((t, i) => (
                <tr key={i}>
                  <td style={{ fontWeight: 600 }}>{t.threat_type}</td>
                  <td>{t.detector}</td>
                  <td><StatusBadge value={t.severity} /></td>
                  <td style={{ fontVariantNumeric: 'tabular-nums' }}>{t.confidence.toFixed(2)}</td>
                  <td style={{ fontVariantNumeric: 'tabular-nums' }}>{t.risk_score.toFixed(2)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  )
}

function Card({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="card card-neutral">
      <div className="card-value">{value}</div>
      <div className="card-label">{label}</div>
    </div>
  )
}
