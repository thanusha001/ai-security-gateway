// Small colored badge for statuses, severities, decisions.

const COLORS: Record<string, string> = {
  // decisions
  ALLOW: '#16a34a', BLOCK: '#dc2626', REDACT: '#d97706', ESCALATE: '#7c3aed',
  SANITIZE: '#2563eb',
  // risk levels
  LOW: '#16a34a', MEDIUM: '#d97706', HIGH: '#ea580c', CRITICAL: '#dc2626',
  // doc/scan statuses
  TRUSTED: '#16a34a', SUSPICIOUS: '#d97706', BLOCKED: '#dc2626', FAILED: '#6b7280',
  PENDING: '#6b7280', SCANNING: '#2563eb', PROCESSING: '#2563eb', COMPLETED: '#16a34a',
  // health
  healthy: '#16a34a', degraded: '#d97706', unhealthy: '#dc2626', unavailable: '#6b7280',
  // severities
  none: '#6b7280', low: '#16a34a', medium: '#d97706', high: '#ea580c', critical: '#dc2626',
}

export function StatusBadge({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="badge badge-muted">—</span>
  const color = COLORS[value.toUpperCase()] ?? COLORS[value] ?? '#6b7280'
  return (
    <span className="badge" style={{ backgroundColor: color }}>
      {value.toUpperCase()}
    </span>
  )
}
