import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider, useAuth } from './hooks/useAuth'
import { Layout } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { Requests } from './pages/Requests'
import { RequestDetail } from './pages/RequestDetail'
import { SecurityEventsPage, ThreatsPage } from './pages/SecurityPages'
import { DocumentsPage } from './pages/Documents'
import { PoliciesPage } from './pages/Policies'
import { AuditPage, HealthPage, LLMUsagePage } from './pages/SystemPages'
import { ChatPage } from './pages/Chat'
import { LoginPage } from './pages/Login'
import type { ReactNode } from 'react'

function RequireAuth({ children }: { children: ReactNode }) {
  const { token } = useAuth()
  if (!token) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route
            path="/"
            element={
              <RequireAuth>
                <Layout />
              </RequireAuth>
            }
          >
            <Route index element={<Dashboard />} />
            <Route path="chat" element={<ChatPage />} />
            <Route path="requests" element={<Requests />} />
            <Route path="requests/:requestId" element={<RequestDetail />} />
            <Route path="events" element={<SecurityEventsPage />} />
            <Route path="threats" element={<ThreatsPage />} />
            <Route path="documents" element={<DocumentsPage />} />
            <Route path="policies" element={<PoliciesPage />} />
            <Route path="llm" element={<LLMUsagePage />} />
            <Route path="audit" element={<AuditPage />} />
            <Route path="health" element={<HealthPage />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}
