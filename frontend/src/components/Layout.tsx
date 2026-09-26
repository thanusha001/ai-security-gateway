import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'

const LINKS: { to: string; label: string; roles?: string[] }[] = [
  { to: '/', label: 'Dashboard' },
  { to: '/requests', label: 'Live Requests' },
  { to: '/events', label: 'Security Events', roles: ['ADMIN', 'AUDITOR'] },
  { to: '/threats', label: 'Threats', roles: ['ADMIN', 'AUDITOR'] },
  { to: '/documents', label: 'Documents' },
  { to: '/policies', label: 'Policies', roles: ['ADMIN', 'AUDITOR'] },
  { to: '/llm', label: 'LLM Usage', roles: ['ADMIN', 'AUDITOR'] },
  { to: '/audit', label: 'Audit Logs', roles: ['ADMIN', 'AUDITOR'] },
  { to: '/health', label: 'System Health' },
]

export function Layout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">
          <h1>AI Security Gateway</h1>
        </div>
        <nav>
          {LINKS.filter((l) => !l.roles || (user && l.roles.includes(user.role))).map((l) => (
            <NavLink key={l.to} to={l.to} end={l.to === '/'}>
              {l.label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          {user ? (
            <>
              <div className="user-info">
                <strong>{user.email}</strong>
                <span className="badge badge-role">{user.role}</span>
              </div>
              <button
                onClick={() => {
                  logout()
                  navigate('/login')
                }}
              >
                Sign out
              </button>
            </>
          ) : (
            <button onClick={() => navigate('/login')}>Sign in</button>
          )}
        </div>
      </aside>
      <main className="content">
        <Outlet />
      </main>
    </div>
  )
}
