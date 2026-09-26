import { createContext, useContext, useState, type ReactNode } from 'react'
import { api, clearAuth, getCurrentUser, setAuth } from '../services/api'
import type { User } from '../types'

interface AuthContextValue {
  token: string | null
  user: User | null
  login: (email: string, password: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextValue>({
  token: null,
  user: null,
  login: async () => {},
  logout: () => {},
})

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<{ token: string | null; user: User | null }>(() => {
    const current = getCurrentUser()
    return {
      token: current?.token ?? null,
      user: current?.user
        ? { ...current.user, role: current.user.role as User['role'], is_active: true }
        : null,
    }
  })

  const login = async (email: string, password: string) => {
    const res = await api.post<{ access_token: string; user: User }>('/auth/login', {
      email,
      password,
    })
    setAuth(res.access_token, res.user)
    setState({ token: res.access_token, user: res.user })
  }

  const logout = () => {
    clearAuth()
    setState({ token: null, user: null })
  }

  return <AuthContext.Provider value={{ ...state, login, logout }}>{children}</AuthContext.Provider>
}

export function useAuth() {
  return useContext(AuthContext)
}
