// Semantic status badge: soft tinted pill + status dot (no saturated fills).
// Tone is derived from the value; unknown values fall back to neutral grey.

const TONES: Record<string, string> = {
  // decisions
  ALLOW: 'ok', COMPLETED: 'ok', ALLOWED: 'ok',
  BLOCK: 'bad', BLOCKED: 'bad',
  REDACT: 'warn', REDACTED: 'warn',
  ESCALATE: 'violet', ESCALATED: 'violet',
  SANITIZE: 'info',
  // risk levels
  LOW: 'ok', MEDIUM: 'warn', HIGH: 'orange', CRITICAL: 'bad',
  // doc/scan statuses
  TRUSTED: 'ok', SUSPICIOUS: 'warn', FAILED: 'neutral',
  PENDING: 'neutral', SCANNING: 'info', PROCESSING: 'info', SUPERSEDED: 'neutral',
  // health
  healthy: 'ok', degraded: 'warn', unhealthy: 'bad', unavailable: 'neutral',
  // severities
  none: 'neutral', low: 'ok', medium: 'warn', high: 'orange', critical: 'bad',
  // misc
  EXACT: 'ok', ESTIMATED: 'warn', UNAVAILABLE: 'neutral',
  ACTIVE: 'ok', INACTIVE: 'neutral',
}

const TONE_CLASS: Record<string, string> = {
  ok: 'badge-ok',
  bad: 'badge-bad',
  warn: 'badge-warn',
  info: 'badge-info',
  orange: 'badge-orange',
  violet: 'badge-violet',
  neutral: 'badge-neutral',
}

export function StatusBadge({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="badge badge-neutral">—</span>
  const tone = TONES[value.toUpperCase()] ?? TONES[value] ?? 'neutral'
  return (
    <span className={`badge ${TONE_CLASS[tone]}`}>
      {value.toUpperCase()}
    </span>
  )
}
