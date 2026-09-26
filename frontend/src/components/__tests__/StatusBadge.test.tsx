import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { StatusBadge } from '../StatusBadge'
import { EmptyState, ErrorState, Unavailable } from '../StateViews'
import { ApiError } from '../../services/api'

describe('StatusBadge', () => {
  it('renders BLOCK in red', () => {
    render(<StatusBadge value="BLOCK" />)
    const badge = screen.getByText('BLOCK')
    expect(badge).toBeInTheDocument()
    expect(badge).toHaveStyle({ backgroundColor: '#dc2626' })
  })

  it('renders a dash for missing values', () => {
    render(<StatusBadge value={null} />)
    expect(screen.getByText('—')).toBeInTheDocument()
  })

  it('renders unknown values in grey', () => {
    render(<StatusBadge value="SOMETHING_NEW" />)
    expect(screen.getByText('SOMETHING_NEW')).toBeInTheDocument()
  })
})

describe('StateViews', () => {
  it('shows empty state message', () => {
    render(<EmptyState message="No requests" />)
    expect(screen.getByText('No requests')).toBeInTheDocument()
  })

  it('shows unavailable state', () => {
    render(<Unavailable message="Ollama is offline" />)
    expect(screen.getByText('Ollama is offline')).toBeInTheDocument()
  })

  it('shows error with request_id for support', () => {
    const err = new ApiError(503, 'LLM_UNAVAILABLE', 'LLM provider is unavailable', 'abc123')
    render(<ErrorState error={err} />)
    expect(screen.getByText('LLM_UNAVAILABLE')).toBeInTheDocument()
    expect(screen.getByText(/request_id: abc123/)).toBeInTheDocument()
  })
})
