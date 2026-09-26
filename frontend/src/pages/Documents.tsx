import { useEffect, useRef, useState } from 'react'
import { api, ApiError } from '../services/api'
import type { ChunkInfo, DocumentInfo } from '../types'
import { EmptyState, ErrorState, Loading } from '../components/StateViews'
import { StatusBadge } from '../components/StatusBadge'
import { useAuth } from '../hooks/useAuth'
import { IconUpload } from '../components/icons'

export function DocumentsPage() {
  const { user } = useAuth()
  const [docs, setDocs] = useState<DocumentInfo[] | null>(null)
  const [error, setError] = useState<ApiError | Error | null>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadResult, setUploadResult] = useState<{ ok: boolean; text: string } | null>(null)
  const [dragging, setDragging] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)
  const canUpload = user?.role === 'ADMIN' || user?.role === 'USER'

  const load = () =>
    api
      .get<DocumentInfo[]>('/documents')
      .then(setDocs)
      .catch(setError)

  useEffect(() => {
    load()
  }, [])

  const handleUpload = async (file: File) => {
    setUploading(true)
    setUploadResult(null)
    try {
      const res = await api.upload<{
        document_id: string | null
        status: string
        detail: string
      }>('/documents/upload', file)
      setUploadResult({ ok: res.status !== 'FAILED', text: `${res.status}: ${res.detail}` })
      await load()
    } catch (e) {
      setUploadResult({ ok: false, text: `Upload failed: ${(e as ApiError).message}` })
    } finally {
      setUploading(false)
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  if (!canUpload) {
    return (
      <div>
        <div className="page-header">
          <div>
            <span className="kicker">Knowledge</span>
            <h2>Documents</h2>
          </div>
        </div>
        <ErrorState error={new Error('Your role does not have access to document management.')} />
      </div>
    )
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <span className="kicker">Knowledge</span>
          <h2>Documents</h2>
          <p className="page-sub">
            Uploads are content-sniffed, chunked, security-scanned per chunk, and deduplicated by
            SHA-256 before entering retrieval.
          </p>
        </div>
      </div>

      {canUpload && (
        <div
          className={`upload-zone${dragging ? ' dragover' : ''}`}
          onClick={() => fileRef.current?.click()}
          onDragOver={(e) => {
            e.preventDefault()
            setDragging(true)
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault()
            setDragging(false)
            const f = e.dataTransfer.files?.[0]
            if (f) handleUpload(f)
          }}
          role="button"
          aria-label="Upload document"
        >
          <input
            ref={fileRef}
            type="file"
            accept=".pdf,.docx,.txt,.md"
            disabled={uploading}
            onChange={(e) => e.target.files?.[0] && handleUpload(e.target.files[0])}
          />
          <div className="uz-icon">{uploading ? <span className="spinner" /> : <IconUpload size={18} />}</div>
          <div className="uz-title">
            {uploading ? 'Uploading & scanning…' : 'Drop a document here, or click to browse'}
          </div>
          <div className="uz-hint">PDF · DOCX · TXT · MD — scanned on ingest, deduped by hash</div>
        </div>
      )}

      {uploadResult && (
        <div className={`notice${uploadResult.ok ? '' : ' is-error'}`}>{uploadResult.text}</div>
      )}
      {error && <ErrorState error={error} />}
      {!error && docs == null && <Loading />}
      {docs != null && docs.length === 0 && (
        <EmptyState
          message="No documents yet"
          hint="Upload a PDF, DOCX, TXT or MD file to build the knowledge base."
        />
      )}

      {docs != null && docs.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>Document</th>
              <th>Type</th>
              <th>Size</th>
              <th>Chunks</th>
              <th>Trust</th>
              <th>Risk</th>
              <th>Status</th>
              <th>Hash</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {docs.map((d) => (
              <DocumentRow key={d.document_id} doc={d} />
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

function DocumentRow({ doc }: { doc: DocumentInfo }) {
  const [open, setOpen] = useState(false)
  const [chunks, setChunks] = useState<ChunkInfo[] | null>(null)
  const [chunkError, setChunkError] = useState<Error | null>(null)

  const toggle = async () => {
    if (!open && chunks == null) {
      try {
        setChunks(await api.get<ChunkInfo[]>(`/documents/${doc.document_id}/chunks`))
      } catch (e) {
        setChunkError(e as ApiError)
      }
    }
    setOpen(!open)
  }

  return (
    <>
      <tr className="expandable" onClick={toggle}>
        <td style={{ fontWeight: 600 }}>{doc.filename}</td>
        <td>{doc.file_type}</td>
        <td>{(doc.file_size / 1024).toFixed(1)} KB</td>
        <td>{doc.chunk_count}</td>
        <td>{doc.trust_score.toFixed(2)}</td>
        <td>{doc.risk_score.toFixed(2)}</td>
        <td><StatusBadge value={doc.status} /></td>
        <td className="mono">{doc.sha256_hash.slice(0, 12)}…</td>
        <td>{open ? '▾' : '▸'}</td>
      </tr>
      {open && (
        <tr>
          <td colSpan={9}>
            {chunkError ? (
              <ErrorState error={chunkError} />
            ) : chunks == null ? (
              <Loading />
            ) : chunks.length === 0 ? (
              <EmptyState message="No chunks" />
            ) : (
              <table className="table inner">
                <thead>
                  <tr>
                    <th>Chunk</th>
                    <th>Page</th>
                    <th>Risk</th>
                    <th>Status</th>
                    <th>Preview</th>
                  </tr>
                </thead>
                <tbody>
                  {chunks.map((c) => (
                    <tr key={c.chunk_id} className={c.security_status !== 'TRUSTED' ? 'row-flagged' : ''}>
                      <td>#{c.chunk_index}</td>
                      <td>{c.page_number ?? '—'}</td>
                      <td>{c.risk_score.toFixed(2)}</td>
                      <td><StatusBadge value={c.security_status} /></td>
                      <td className="reason-cell">{c.text_preview}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </td>
        </tr>
      )}
    </>
  )
}
