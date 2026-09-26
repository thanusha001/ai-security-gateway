import { useEffect, useState } from 'react'
import { api, ApiError } from '../services/api'
import type { PolicyInfo } from '../types'
import { EmptyState, ErrorState, Loading } from '../components/StateViews'
import { StatusBadge } from '../components/StatusBadge'
import { useAuth } from '../hooks/useAuth'

const DEFAULT_RULES: Record<string, { threshold: number; action: string }> = {
  prompt_injection: { threshold: 0.6, action: 'BLOCK' },
  jailbreak: { threshold: 0.5, action: 'BLOCK' },
  secret_detection: { threshold: 0.3, action: 'REDACT' },
  pii_detection: { threshold: 0.3, action: 'REDACT' },
  document_poisoning: { threshold: 0.6, action: 'BLOCK' },
  system_prompt_leakage: { threshold: 0.6, action: 'REDACT' },
  unsafe_content: { threshold: 0.7, action: 'BLOCK' },
}

const ACTIONS = ['ALLOW', 'REDACT', 'SANITIZE', 'ESCALATE', 'BLOCK']

export function PoliciesPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'ADMIN'
  const [policies, setPolicies] = useState<PolicyInfo[] | null>(null)
  const [error, setError] = useState<ApiError | Error | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)

  const load = () =>
    api
      .get<PolicyInfo[]>('/policies')
      .then(setPolicies)
      .catch(setError)

  useEffect(() => {
    load()
  }, [])

  const activate = async (p: PolicyInfo, deactivate = false) => {
    setNotice(null)
    try {
      await api.post(`/policies/${p.id}/${deactivate ? 'deactivate' : 'activate'}`)
      setNotice(`Policy ${p.name} v${p.version} ${deactivate ? 'deactivated' : 'activated'}`)
      await load()
    } catch (e) {
      setNotice(`Failed: ${(e as ApiError).message}`)
    }
  }

  if (error) return <ErrorState error={error} />
  if (!policies) return <Loading />

  return (
    <div>
      <div className="page-header">
        <h2>Security Policies</h2>
        {isAdmin && (
          <button onClick={() => setCreating(!creating)}>
            {creating ? 'Cancel' : 'New policy'}
          </button>
        )}
      </div>

      {notice && <div className="notice">{notice}</div>}

      {creating && isAdmin && (
        <PolicyEditor
          onDone={(msg) => {
            setCreating(false)
            setNotice(msg)
            load()
          }}
        />
      )}

      {policies.length === 0 ? (
        <EmptyState message="No policies defined (gateway falls back to built-in defaults)" />
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Version</th>
              <th>Status</th>
              <th>Rules</th>
              <th>Updated</th>
              {isAdmin && <th>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {policies.map((p) => (
              <tr key={p.id}>
                <td>{p.name}</td>
                <td>v{p.version}</td>
                <td>{p.is_active ? <StatusBadge value="ACTIVE" /> : 'inactive'}</td>
                <td>{Object.keys(p.configuration.rules).length} rules</td>
                <td>{p.updated_at ? new Date(p.updated_at).toLocaleString() : '—'}</td>
                {isAdmin && (
                  <td>
                    {p.is_active ? (
                      <button onClick={() => activate(p, true)}>Deactivate</button>
                    ) : (
                      <button onClick={() => activate(p)}>Activate</button>
                    )}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

function PolicyEditor({ onDone }: { onDone: (message: string) => void }) {
  const [name, setName] = useState('')
  const [rules, setRules] = useState(DEFAULT_RULES)
  const [allowSuspicious, setAllowSuspicious] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async () => {
    setError(null)
    if (name.trim().length < 3) {
      setError('Policy name must be at least 3 characters')
      return
    }
    try {
      const res = await api.post<PolicyInfo>('/policies', {
        name: name.trim(),
        configuration: {
          rules,
          risk_thresholds: { medium: 0.3, high: 0.6, critical: 0.8 },
          allow_suspicious_chunks: allowSuspicious,
          fail_closed_on_context_uncertainty: true,
        },
      })
      onDone(`Created ${res.name} v${res.version} (inactive — activate when ready)`)
    } catch (e) {
      setError((e as ApiError).message)
    }
  }

  return (
    <section className="panel">
      <h3>New Policy</h3>
      {error && <div className="state state-error">{error}</div>}
      <label>
        Name{' '}
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="strict-policy" />
      </label>
      <table className="table inner">
        <thead>
          <tr>
            <th>Threat rule</th>
            <th>Threshold (0–1)</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {Object.entries(rules).map(([threat, rule]) => (
            <tr key={threat}>
              <td>{threat}</td>
              <td>
                <input
                  type="number"
                  min={0}
                  max={1}
                  step={0.05}
                  value={rule.threshold}
                  onChange={(e) =>
                    setRules({
                      ...rules,
                      [threat]: { ...rule, threshold: Number(e.target.value) },
                    })
                  }
                />
              </td>
              <td>
                <select
                  value={rule.action}
                  onChange={(e) =>
                    setRules({
                      ...rules,
                      [threat]: { ...rule, action: e.target.value },
                    })
                  }
                >
                  {ACTIONS.map((a) => (
                    <option key={a}>{a}</option>
                  ))}
                </select>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <label>
        <input
          type="checkbox"
          checked={allowSuspicious}
          onChange={(e) => setAllowSuspicious(e.target.checked)}
        />{' '}
        allow SUSPICIOUS chunks into retrieval context (not recommended)
      </label>
      <button onClick={submit}>Create policy</button>
    </section>
  )
}
