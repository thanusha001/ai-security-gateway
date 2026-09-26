import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import { ApiError } from '../services/api'
import { IconLock } from '../components/icons'

export function LoginPage() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await login(email, password)
      navigate('/')
    } catch (err) {
      const apiErr = err as ApiError
      setError(apiErr.code === 'AUTHENTICATION_FAILED'
        ? 'Invalid email or password'
        : apiErr.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-page">
      <form className="login-card" onSubmit={submit}>
        <div className="login-brand">
          <div className="brand-mark">
            <IconLock size={18} />
          </div>
          <div>
            <h2>Security Gateway</h2>
            <span className="brand-sub">Operator access</span>
          </div>
        </div>

        {error && (
          <div className="state state-error" role="alert" style={{ margin: 0 }}>
            <strong>Sign-in failed</strong>
            <p>{error}</p>
          </div>
        )}

        <label>
          Email
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="username"
            placeholder="you@company.com"
            required
          />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            placeholder="••••••••••••"
            required
          />
        </label>
        <button type="submit" className="btn-primary" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
        <p className="login-hint">
          Credentials are provisioned at bootstrap via <span className="mono">ADMIN_EMAIL</span> /{' '}
          <span className="mono">ADMIN_PASSWORD</span>. Change the defaults before any real use.
        </p>
      </form>
    </div>
  )
}
