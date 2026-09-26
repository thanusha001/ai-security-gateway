// Shared types mirroring the backend API responses.

export type Role = 'ADMIN' | 'USER' | 'AUDITOR'

export interface User {
  id: number
  email: string
  role: Role
  is_active: boolean
}

export interface AuthState {
  token: string | null
  user: User | null
}

export interface SecurityEvent {
  id?: number
  request_id: string
  stage: string
  event_type: string
  status: string
  severity?: string | null
  confidence?: number | null
  risk_score?: number | null
  action?: string | null
  detector?: string | null
  detector_version?: string | null
  reason?: string | null
  evidence?: Record<string, unknown> | null
  latency_ms?: number | null
  created_at?: string | null
}

export interface Threat {
  request_id: string
  threat_type: string
  severity: string
  confidence: number
  risk_score: number
  detector: string
  evidence?: Record<string, unknown> | null
  created_at?: string | null
}

export interface RequestSummary {
  request_id: string
  user_id: number | null
  status: string
  risk_score: number
  risk_level: string
  final_decision: string | null
  policy_version: number | null
  total_latency_ms: number | null
  created_at: string
  input_preview: string
}

export interface RetrievalInfo {
  document_id: string
  chunk_id: number
  similarity: number | null
  included: boolean
  exclusion_reason: string | null
  security_status: string | null
}

export interface LLMInfo {
  provider: string
  model: string
  input_tokens: number | null
  output_tokens: number | null
  total_tokens: number | null
  token_count_source: string | null
  generation_latency_ms: number | null
  tokens_per_second: number | null
  status: string
  error_code: string | null
}

export interface RequestDetail {
  request: {
    request_id: string
    user_id: number | null
    status: string
    risk_score: number
    risk_level: string
    final_decision: string | null
    policy_id: number | null
    policy_version: number | null
    total_latency_ms: number | null
    error_code: string | null
    started_at: string | null
    completed_at: string | null
    input_text: string | null
    response_text: string | null
  }
  events: SecurityEvent[]
  retrievals: RetrievalInfo[]
  llm: LLMInfo[]
  threats: Threat[]
}

export interface Metrics {
  total_requests: number
  allowed_requests: number
  blocked_requests: number
  redacted_requests: number
  escalated_requests: number
  threat_count: number
  average_risk_score: number | null
  average_latency_ms: number | null
  p95_latency_ms: number | null
  llm_requests: number
  total_input_tokens: number | null
  total_output_tokens: number | null
  total_tokens: number | null
  detector_counts: Record<string, number>
}

export interface DocumentInfo {
  document_id: string
  filename: string
  sha256_hash: string
  file_type: string
  file_size: number
  source: string | null
  status: string
  trust_score: number
  risk_score: number
  chunk_count: number
  created_at: string | null
  updated_at: string | null
}

export interface ChunkInfo {
  chunk_id: number
  chunk_index: number
  page_number: number | null
  security_status: string
  risk_score: number
  reason: string | null
  text_preview: string | null
}

export interface PolicyInfo {
  id: number
  name: string
  version: number
  description: string | null
  configuration: {
    rules: Record<string, { threshold: number; action: string }>
    risk_thresholds?: Record<string, number>
    allow_suspicious_chunks?: boolean
    fail_closed_on_context_uncertainty?: boolean
  }
  is_active: boolean
  created_at: string | null
  updated_at: string | null
}

export interface AuditEntry {
  id: number
  user_id: number | null
  request_id: string | null
  action: string
  resource_type: string | null
  resource_id: string | null
  details: Record<string, unknown> | null
  created_at: string | null
}

export interface HealthInfo {
  status: 'healthy' | 'degraded' | 'unhealthy'
  components: Record<string, string>
}

export interface LLMUsage {
  models: {
    model: string
    provider: string
    requests: number
    input_tokens: number
    output_tokens: number
    total_tokens: number
    avg_generation_ms: number | null
    avg_tokens_per_second: number | null
    failures: number
  }[]
  token_count_sources: Record<string, number>
}

export interface ChatResult {
  request_id: string
  response: string | null
  final_decision: string
  risk_score: number
  risk_level: string
  policy_name: string | null
  policy_version: number | null
  total_latency_ms: number
  blocked_reason: string | null
  redacted: boolean
}

export interface PipelineEvent {
  request_id: string
  stage: string
  status: string
  duration_ms?: number
  ts?: string
  [key: string]: unknown
}
