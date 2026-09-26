import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import { useHealth } from '../hooks/useHealth'
import {
  IconGauge, IconTerminal, IconPulse, IconShield, IconBug, IconDocs,
  IconSliders, IconChip, IconScroll, IconHeart, IconLogout, IconLock,
} from './icons'

const NAV: { group: string; links: { to: string; label: string; icon: React.ReactNode; roles?: string[] }[] }[] = [
  {
    group: 'Monitor',
    links: [
      { to: '/', label: 'Dashboard', icon: <IconGauge /> },
      { to: '/requests', label: 'Live Requests', icon: <IconPulse /> },
    ],
  },
  {
    group: 'Security',
    links: [
      { to: '/events', label: 'Security Events', icon: <IconShield />, roles: ['ADMIN', 'AUDITOR'] },
      { to: '/threats', label: 'Threats', icon: <IconBug />, roles: ['ADMIN', 'AUDITOR'] },
      { to: '/policies', label: 'Policies', icon: <IconSliders />, roles: ['ADMIN', 'AUDITOR'] },
    ],
  },
  {
    group: 'Knowledge',
    links: [
      { to: '/documents', label: 'Documents', icon: <IconDocs /> },
    ],
  },
  {
    group: 'Platform',
    links: [
      { to: '/chat', label: 'Gateway Console', icon: <IconTerminal /> },
      { to: '/llm', label: 'LLM Usage', icon: <IconChip />, roles: ['ADMIN', 'AUDITOR'] },
      { to: '/audit', label: 'Audit Logs', icon: <IconScroll />, roles: ['ADMIN', 'AUDITOR'] },
      { to: '/health', label: 'System Health', icon: <IconHeart /> },
    ],
  },
]

const TITLES: Record<string, { title: string; sub: string }> = {
  '/': { title: 'Security Dashboard', sub: 'Live posture across the gateway pipeline' },
  '/requests': { title: 'Live Requests', sub: 'Real-time pipeline traces and recent traffic' },
  '/events': { title: 'Security Events', sub: 'Detector findings across all stages' },
  '/threats': { title: 'Threat Detections', sub: 'Correlated detections from the security pipeline' },
  '/documents': { title: 'Knowledge Base', sub: 'Ingested documents with per-chunk security scanning' },
  '/policies': { title: 'Security Policies', sub: 'Versioned rules evaluated on every request' },
  '/llm': { title: 'LLM Usage', sub: 'Model calls, token accounting, and throughput' },
  '/audit': { title: 'Audit Log', sub: 'Security-relevant actions, immutable trail' },
  '/health': { title: 'System Health', sub: 'Component status for the gateway stack' },
  '/chat': { title: 'Gateway Console', sub: 'Exercise the full security pipeline end-to-end' },
}

const HEALTH_LABEL: Record<string, string> = {
  healthy: 'All systems normal',
  degraded: 'Degraded — reduced capability',
  unhealthy: 'System unhealthy',
}

const HEALTH_DOT: Record<string, string> = {
  healthy: 'var(--accent)',
  degraded: 'var(--warn)',
  unhealthy: 'var(--bad)',
}

export function Layout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const { health } = useHealth()
  const location = useLocation()
  const meta = TITLES[location.pathname] ?? { title: 'AI Security Gateway', sub: '' }
  const initials = user
    ? user.email.slice(0, 2).toUpperCase()
    : '??'

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <IconLock size={17} />
          </div>
          <div>
            <h1 className="brand-name">Security Gateway</h1>
            <span className="brand-sub">LLM · RAG Shield</span>
          </div>
        </div>
        <nav>
          {NAV.map((section) => {
            const visible = section.links.filter(
              (l) => !l.roles || (user && l.roles.includes(user.role)),
            )
            if (visible.length === 0) return null
            return (
              <div className="nav-group" key={section.group}>
                <div className="nav-label">{section.group}</div>
                {visible.map((l) => (
                  <NavLink key={l.to} to={l.to} end={l.to === '/'} className="nav-link">
                    {l.icon}
                    <span>{l.label}</span>
                  </NavLink>
                ))}
              </div>
            )
          })}
        </nav>
        <div className="sidebar-footer">
          {user ? (
            <div className="user-card">
              <div className="avatar">{initials}</div>
              <div className="user-meta">
                <span className="user-email">{user.email}</span>
                <span className="user-role">{user.role}</span>
              </div>
              <button
                className="icon-btn"
                title="Sign out"
                aria-label="Sign out"
                onClick={() => {
                  logout()
                  navigate('/login')
                }}
              >
                <IconLogout size={15} />
              </button>
            </div>
          ) : (
            <button className="btn-ghost" onClick={() => navigate('/login')}>Sign in</button>
          )}
        </div>
      </aside>

      <div className="main-col">
        <header className="topbar">
          <div>
            <h2 className="topbar-title">{meta.title}</h2>
          </div>
          <span className="topbar-spacer" />
          {health && (
            <span
              className="env-chip"
              title={Object.entries(health.components).map(([k, v]) => `${k}: ${v}`).join('\n')}
            >
              <span className="dot" style={{ background: HEALTH_DOT[health.status] ?? 'var(--text-faint)' }} />
              {HEALTH_LABEL[health.status] ?? health.status}
            </span>
          )}
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
