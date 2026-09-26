// Central API client. Attaches the JWT, parses the standard error envelope,
// and never leaks raw stack traces to UI components.

const API_BASE = '/api/v1'

export class ApiError extends Error {
  code: string
  requestId: string | null
  status: number

  constructor(status: number, code: string, message: string, requestId: string | null) {
    super(message)
    this.status = status
    this.code = code
    this.requestId = requestId
  }
}

function getToken(): string | null {
  return localStorage.getItem('gateway_token')
}

export function setAuth(token: string, user: unknown): void {
  localStorage.setItem('gateway_token', token)
  localStorage.setItem('gateway_user', JSON.stringify(user))
}

export function clearAuth(): void {
  localStorage.removeItem('gateway_token')
  localStorage.removeItem('gateway_user')
}

export function getCurrentUser(): { token: string; user: { id: number; email: string; role: string } } | null {
  const token = getToken()
  const userJson = localStorage.getItem('gateway_user')
  if (!token || !userJson) return null
  try {
    return { token, user: JSON.parse(userJson) }
  } catch {
    return null
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    ...(options.headers as Record<string, string>),
  }
  const token = getToken()
  if (token) headers['Authorization'] = `Bearer ${token}`
  if (options.body && typeof options.body === 'string') {
    headers['Content-Type'] = 'application/json'
  }

  let response: Response
  try {
    response = await fetch(`${API_BASE}${path}`, { ...options, headers })
  } catch {
    throw new ApiError(0, 'NETWORK_ERROR', 'Backend is unreachable', null)
  }

  if (response.status === 204) return {} as T

  let body: unknown
  try {
    body = await response.json()
  } catch {
    body = null
  }

  if (!response.ok) {
    // Standard envelope: {"error": {"code", "message", "request_id", ...}}
    // FastAPI HTTPException detail also lands here via our handlers.
    const err = (body as { error?: { code?: string; message?: string; request_id?: string } })?.error
      ?? (body as { detail?: { code?: string; message?: string; request_id?: string } })?.detail
      ?? (body as { detail?: string })
    const code = (err as { code?: string })?.code ?? 'HTTP_ERROR'
    const message = (err as { message?: string })?.message
      ?? (typeof (body as { detail?: string })?.detail === 'string'
        ? (body as { detail: string }).detail
        : `Request failed with status ${response.status}`)
    const requestId = (err as { request_id?: string })?.request_id ?? null
    if (response.status === 401) clearAuth()
    throw new ApiError(response.status, code, message, requestId)
  }

  return body as T
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'POST', body: body ? JSON.stringify(body) : undefined }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'PUT', body: body ? JSON.stringify(body) : undefined }),
  upload: async <T>(path: string, file: File): Promise<T> => {
    const form = new FormData()
    form.append('file', file)
    const headers: Record<string, string> = {}
    const token = getToken()
    if (token) headers['Authorization'] = `Bearer ${token}`
    const response = await fetch(`${API_BASE}${path}`, { method: 'POST', body: form, headers })
    const body = await response.json().catch(() => null)
    if (!response.ok) {
      const err = (body as { detail?: { code?: string; message?: string } })?.detail
      throw new ApiError(response.status, err?.code ?? 'HTTP_ERROR',
        err?.message ?? `Upload failed (${response.status})`, null)
    }
    return body as T
  },
}
