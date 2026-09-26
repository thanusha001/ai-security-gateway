// Explicit UI states: loading / error / empty / unauthorized (spec §55).
// No blank screens; errors show request_id for debugging.

import type { ApiError } from '../services/api'

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return <div className="state state-loading">{label}</div>
}

export function Processing({ label = 'Processing…' }: { label?: string }) {
  return (
    <div className="state state-processing">
      <span className="spinner" /> {label}
    </div>
  )
}

export function EmptyState({ message = 'No data' }: { message?: string }) {
  return <div className="state state-empty">{message}</div>
}

export function Unavailable({ message = 'Component unavailable' }: { message?: string }) {
  return <div className="state state-unavailable">{message}</div>
}

export function ErrorState({ error }: { error: ApiError | Error | null }) {
  if (!error) return null
  const requestId = 'requestId' in error ? (error as ApiError).requestId : null
  const code = 'code' in error ? (error as ApiError).code : 'ERROR'
  return (
    <div className="state state-error" role="alert">
      <strong>{code}</strong>
      <p>{error.message}</p>
      {requestId && <small>request_id: {requestId}</small>}
    </div>
  )
}
