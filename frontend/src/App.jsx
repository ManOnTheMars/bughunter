import { useState } from 'react'
import {
  Bug, ShieldAlert, Search, FolderSearch, Loader2, FileCode,
  ChevronDown, CheckCircle2, AlertTriangle,
} from 'lucide-react'

const SEVERITY = {
  Critical: { dot: 'bg-critical', text: 'text-critical', badge: 'bg-critical/15 text-critical border-critical/30', rank: 0 },
  High:     { dot: 'bg-high',     text: 'text-high',     badge: 'bg-high/15 text-high border-high/30',         rank: 1 },
  Medium:   { dot: 'bg-medium',   text: 'text-medium',   badge: 'bg-medium/15 text-medium border-medium/30',   rank: 2 },
  Low:      { dot: 'bg-low',      text: 'text-low',      badge: 'bg-low/15 text-low border-low/30',            rank: 3 },
}
const CAT_STYLE = {
  Security: 'bg-fuchsia-500/15 text-fuchsia-300',
  Logic:    'bg-sky-500/15 text-sky-300',
}
const MODES = [
  { key: 'all', label: 'Бүгд' },
  { key: 'security', label: 'Аюулгүй байдал' },
  { key: 'logic', label: 'Логик алдаа' },
]

function StatCard({ label, value, tone }) {
  return (
    <div className="card flex flex-col gap-1">
      <span className="text-[11px] uppercase tracking-widest text-slate-400">{label}</span>
      <span className={`text-2xl font-semibold num ${tone ?? 'text-slate-100'}`}>{value}</span>
    </div>
  )
}

function FindingCard({ f }) {
  const [open, setOpen] = useState(true)
  const sev = SEVERITY[f.severity]
  return (
    <div className="bg-surface-900/60 border border-surface-700/60 rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-surface-800/50 transition-colors"
      >
        <span className={`w-2 h-2 rounded-full shrink-0 ${sev.dot}`} />
        <span className={`text-[11px] px-2 py-0.5 rounded-full font-semibold border ${sev.badge}`}>{f.severity}</span>
        <span className={`text-[11px] px-2 py-0.5 rounded-full ${CAT_STYLE[f.category]}`}>{f.category}</span>
        <span className="font-medium text-sm flex-1 truncate">{f.title}</span>
        <span className="num text-xs text-slate-500 shrink-0">
          {f.file}{f.line ? `:${f.line}` : ''}
        </span>
        <ChevronDown size={15} className={`text-slate-500 transition-transform shrink-0 ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div className="px-4 pb-3 pl-9 space-y-2">
          <p className="text-sm text-slate-300 leading-relaxed">{f.description}</p>
          <p className="text-sm text-slate-200 leading-relaxed border-t border-surface-700/60 pt-2">
            <span className="text-accent font-semibold">Засвар: </span>{f.recommendation}
          </p>
          <span className="text-[11px] text-slate-500">Итгэл: {f.confidence}</span>
        </div>
      )}
    </div>
  )
}

export default function App() {
  const [path, setPath] = useState('')
  const [mode, setMode] = useState('all')
  const [maxFiles, setMaxFiles] = useState(40)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)

  async function scan() {
    if (!path.trim()) return
    setLoading(true); setError(null); setResult(null)
    try {
      const r = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: path.trim(), mode, max_files: Number(maxFiles) }),
      })
      const data = await r.json()
      if (!r.ok) throw new Error(typeof data.detail === 'string' ? data.detail : `${r.status} ${r.statusText}`)
      setResult(data)
    } catch (e) {
      setError(e.message === 'Failed to fetch' ? 'Backend ажиллахгүй байна (port 8000)' : e.message)
    } finally {
      setLoading(false)
    }
  }

  const s = result?.summary

  return (
    <div className="min-h-dvh">
      {/* Top bar */}
      <header className="sticky top-0 z-40 bg-surface-950/80 backdrop-blur-md border-b border-surface-600/40">
        <div className="px-6 h-14 flex items-center gap-2 max-w-[1400px] mx-auto">
          <span className="flex items-center justify-center w-7 h-7 rounded-lg bg-critical/15 text-critical">
            <Bug size={16} />
          </span>
          <span className="font-semibold tracking-tight text-sm">Bug<span className="text-critical">Hunter</span></span>
          <span className="ml-auto text-[11px] text-slate-500 uppercase tracking-widest hidden sm:block">
            Claude Opus · Security + Logic
          </span>
        </div>
      </header>

      <main className="p-6 max-w-[1400px] mx-auto space-y-6 animate-fade-in">
        {/* Scan controls */}
        <div className="card space-y-3">
          <div className="flex items-center gap-2 text-slate-400">
            <FolderSearch size={15} />
            <span className="text-[11px] uppercase tracking-widest">Локал замыг шинжлэх</span>
          </div>
          <div className="flex flex-col md:flex-row gap-2">
            <input
              className="input flex-1 num"
              placeholder="C:\Users\me\my-project   эсвэл   ./src"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && !loading && scan()}
              aria-label="Scan path"
            />
            <div className="flex gap-1 bg-surface-900 border border-surface-600/60 rounded-lg p-1">
              {MODES.map((m) => (
                <button
                  key={m.key}
                  onClick={() => setMode(m.key)}
                  className={`text-xs font-medium px-3 py-1.5 rounded transition-colors ${
                    mode === m.key ? 'bg-accent text-white' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {m.label}
                </button>
              ))}
            </div>
            <input
              type="number" min="1" max="500"
              className="input w-24 num" value={maxFiles}
              onChange={(e) => setMaxFiles(e.target.value)}
              aria-label="Max files" title="Хамгийн их файлын тоо"
            />
            <button onClick={scan} disabled={loading || !path.trim()} className="btn-primary justify-center">
              {loading ? <Loader2 size={15} className="animate-spin" /> : <Search size={15} />}
              {loading ? 'Шинжилж байна…' : 'Шинжлэх'}
            </button>
          </div>
          {error && (
            <p className="flex items-center gap-1.5 text-sm text-critical">
              <AlertTriangle size={14} /> {error}
            </p>
          )}
          {loading && (
            <p className="text-xs text-slate-500">
              Claude Opus файл бүрийг шинжилж байна — кодын хэмжээнээс хамаарч хэдэн арван секунд болж магадгүй.
            </p>
          )}
        </div>

        {/* Summary */}
        {s && (
          <>
            <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
              <StatCard label="Нийт олдсон" value={s.total_findings} tone={s.total_findings ? 'text-slate-100' : 'text-low'} />
              <StatCard label="Critical" value={s.by_severity.Critical} tone={s.by_severity.Critical ? 'text-critical' : 'text-slate-500'} />
              <StatCard label="High" value={s.by_severity.High} tone={s.by_severity.High ? 'text-high' : 'text-slate-500'} />
              <StatCard label="Medium" value={s.by_severity.Medium} tone={s.by_severity.Medium ? 'text-medium' : 'text-slate-500'} />
              <StatCard label="Аюулгүй / Логик" value={`${s.by_category.Security} / ${s.by_category.Logic}`} />
              <StatCard label="Файл" value={`${s.files_scanned}`} tone="text-slate-300" />
            </div>

            {/* Findings */}
            <div className="card space-y-2">
              <div className="flex items-center gap-2 text-slate-400 mb-1">
                <ShieldAlert size={15} />
                <span className="text-[11px] uppercase tracking-widest">Олдсон асуудлууд</span>
              </div>
              {result.findings.length === 0 ? (
                <div className="flex flex-col items-center gap-2 py-12 text-slate-400">
                  <CheckCircle2 size={28} className="text-low" />
                  <p className="text-sm">Асуудал олдсонгүй — {s.files_scanned} файл цэвэрхэн.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {result.findings.map((f, i) => <FindingCard key={i} f={f} />)}
                </div>
              )}
              {s.files_skipped > 0 && (
                <p className="text-[11px] text-slate-600 pt-1">
                  {s.files_skipped} файл алгассан (хэт том, хоосон, эсвэл дэмжээгүй төрөл).
                </p>
              )}
            </div>
          </>
        )}

        {/* Empty initial state */}
        {!s && !loading && (
          <div className="card flex flex-col items-center gap-3 py-16 text-slate-400">
            <FileCode size={32} className="text-slate-600" />
            <p className="text-sm">Локал фолдер эсвэл файлын замыг оруулаад <span className="text-accent font-medium">Шинжлэх</span> дарна уу.</p>
            <p className="text-xs text-slate-600 max-w-md text-center">
              Claude Opus код доторх аюулгүй байдлын эмзэг (injection, secrets, XSS…) болон
              логик алдаа (null deref, race condition, edge case…)-г илрүүлнэ.
            </p>
          </div>
        )}
      </main>
    </div>
  )
}
