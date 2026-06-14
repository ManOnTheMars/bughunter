import { useState, useRef, useEffect } from 'react'
import {
  Bug, ShieldAlert, Search, FolderSearch, Loader2, FileCode,
  ChevronDown, CheckCircle2, AlertTriangle, Square, Plus, History,
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
const SEV_KEYS = ['All', 'Critical', 'High', 'Medium', 'Low']
const HISTORY_KEY = 'bughunter.scans'
const HISTORY_CAP = 20

// ---- helpers ----
const bySeverity = (a, b) =>
  SEVERITY[a.severity].rank - SEVERITY[b.severity].rank ||
  a.file.localeCompare(b.file) || a.line - b.line

function summarize(findings, root, filesScanned, filesSkipped) {
  const by_severity = { Critical: 0, High: 0, Medium: 0, Low: 0 }
  const by_category = { Security: 0, Logic: 0 }
  for (const f of findings) { by_severity[f.severity]++; by_category[f.category]++ }
  return {
    root, files_scanned: filesScanned, files_skipped: filesSkipped,
    total_findings: findings.length, by_severity, by_category,
  }
}

function shortPath(p) {
  const parts = p.replace(/[/\\]+$/, '').split(/[/\\]/)
  return parts.slice(-2).join('/') || p
}

function loadHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [] }
  catch { return [] }
}

// ---- small components ----
function ProgressBar({ done, total, file }) {
  const pct = total ? Math.round((done / total) * 100) : 0
  return (
    <div className="space-y-1.5">
      <div className="flex justify-between gap-3 text-[11px] text-slate-400">
        <span className="truncate num">{file ? `▸ ${file}` : 'Файлуудыг цуглуулж байна…'}</span>
        <span className="num shrink-0">{done}/{total} · {pct}%</span>
      </div>
      <div className="h-1.5 rounded-full bg-surface-700/60 overflow-hidden">
        <div className="h-full bg-accent rounded-full transition-all duration-300 ease-out" style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

function StatCard({ label, value, tone }) {
  return (
    <div className="card flex flex-col gap-1">
      <span className="text-[11px] uppercase tracking-widest text-slate-400">{label}</span>
      <span className={`text-2xl font-semibold num ${tone ?? 'text-slate-100'}`}>{value}</span>
    </div>
  )
}

function SeverityFilter({ value, onChange, counts }) {
  return (
    <div className="flex gap-1 flex-wrap">
      {SEV_KEYS.map((k) => {
        const active = value === k
        const sev = SEVERITY[k]
        return (
          <button
            key={k}
            onClick={() => onChange(k)}
            className={`text-[11px] px-2.5 py-1 rounded-full border transition-colors ${
              active
                ? (sev ? sev.badge : 'bg-accent/15 text-accent border-accent/30')
                : 'border-surface-700/60 text-slate-400 hover:text-slate-200'
            }`}
          >
            {k === 'All' ? 'Бүгд' : k}{k !== 'All' && counts ? ` ${counts[k] || 0}` : ''}
          </button>
        )
      })}
    </div>
  )
}

function FindingCard({ f }) {
  const [open, setOpen] = useState(true)
  const sev = SEVERITY[f.severity]
  return (
    <div className="bg-surface-900/60 border border-surface-700/60 rounded-lg overflow-hidden animate-fade-in">
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

function HistoryTabs({ history, activeId, running, onSelect, onNew }) {
  if (!history.length && !running) return null
  return (
    <div className="flex gap-1 items-center overflow-x-auto pb-1">
      <History size={14} className="text-slate-500 shrink-0" />
      <button
        onClick={onNew}
        className={`flex items-center gap-1 text-xs px-2.5 py-1 rounded-lg border shrink-0 transition-colors ${
          !running && activeId === null
            ? 'bg-accent/15 text-accent border-accent/30'
            : 'border-surface-700/60 text-slate-400 hover:text-slate-200'
        }`}
      >
        <Plus size={13} /> Шинэ
      </button>
      {running && (
        <span className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-lg border border-accent/30 text-accent shrink-0">
          <Loader2 size={12} className="animate-spin" /> Идэвхтэй
        </span>
      )}
      {history.map((h) => (
        <button
          key={h.id}
          onClick={() => onSelect(h.id)}
          title={h.path}
          className={`flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-lg border shrink-0 transition-colors ${
            !running && activeId === h.id
              ? 'bg-surface-700/60 text-slate-100 border-surface-600'
              : 'border-surface-700/60 text-slate-400 hover:text-slate-200'
          }`}
        >
          <span className="num truncate max-w-[150px]">{shortPath(h.path)}</span>
          {h.partial && <span className="text-medium text-[10px]">хагас</span>}
        </button>
      ))}
    </div>
  )
}

export default function App() {
  const [path, setPath] = useState('')
  const [mode, setMode] = useState('all')
  const [maxFiles, setMaxFiles] = useState(40)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState(null)
  const [progress, setProgress] = useState(null)         // {done,total,file,files_skipped,root}
  const [liveFindings, setLiveFindings] = useState([])
  const [history, setHistory] = useState(loadHistory)
  const [activeId, setActiveId] = useState(null)
  const [sevFilter, setSevFilter] = useState('All')
  const [model, setModel] = useState(null)
  const esRef = useRef(null)

  // Active model label for the header.
  useEffect(() => {
    fetch('/api/health')
      .then((r) => r.json())
      .then((d) => {
        if (d.provider === 'ollama') setModel(`Ollama · ${String(d.model).replace(/^ollama:/, '')}`)
        else setModel(`Claude · ${d.model}`)
      })
      .catch(() => setModel(null))
  }, [])

  // Clean up any open stream on unmount.
  useEffect(() => () => esRef.current?.close(), [])

  function persist(next) {
    setHistory(next)
    try { localStorage.setItem(HISTORY_KEY, JSON.stringify(next)) } catch { /* quota */ }
  }

  function finishScan(scanObj) {
    const next = [scanObj, ...history].slice(0, HISTORY_CAP)
    persist(next)
    setActiveId(scanObj.id)
    setRunning(false)
    setLiveFindings([])
    setProgress(null)
  }

  function closeStream() {
    esRef.current?.close()
    esRef.current = null
  }

  function scan() {
    if (!path.trim() || running) return
    closeStream()
    const root = path.trim()
    setRunning(true); setError(null); setLiveFindings([]); setActiveId(null); setSevFilter('All')
    setProgress({ done: 0, total: 0, file: null, files_skipped: 0, root })

    const qs = new URLSearchParams({ path: root, mode, max_files: String(Number(maxFiles)) })
    const es = new EventSource('/api/scan/stream?' + qs)
    esRef.current = es
    let collected = []
    let meta = { root, files_skipped: 0, total: 0 }
    let finished = false

    es.addEventListener('meta', (e) => {
      meta = JSON.parse(e.data)
      setProgress({ done: 0, total: meta.total, file: null, files_skipped: meta.files_skipped, root: meta.root })
    })
    es.addEventListener('finding', (e) => {
      collected = [...collected, JSON.parse(e.data).finding]
      setLiveFindings(collected)
    })
    es.addEventListener('progress', (e) => {
      const p = JSON.parse(e.data)
      setProgress((prev) => ({ ...prev, done: p.done, total: p.total, file: p.file }))
    })
    es.addEventListener('done', (e) => {
      finished = true
      const data = JSON.parse(e.data)
      closeStream()
      finishScan({
        id: `${Date.now()}-${Math.round(Math.random() * 1e6)}`,
        path: meta.root, mode, ts: Date.now(),
        result: { summary: data.summary, findings: data.findings },
      })
    })
    es.addEventListener('error', (e) => {
      if (finished) return                 // server closed cleanly after 'done'
      let msg = 'Backend ажиллахгүй байна (port 8000)'
      if (e.data) { try { msg = JSON.parse(e.data).detail } catch { /* keep default */ } }
      closeStream()
      setError(msg)
      setRunning(false)
      setProgress(null)
    })
  }

  function stop() {
    closeStream()
    // Freeze partial results into history so they aren't lost.
    if (liveFindings.length || progress) {
      finishScan({
        id: `${Date.now()}-${Math.round(Math.random() * 1e6)}`,
        path: progress?.root || path.trim(), mode, ts: Date.now(), partial: true,
        result: {
          summary: summarize(liveFindings, progress?.root || path.trim(), progress?.done || 0, progress?.files_skipped || 0),
          findings: [...liveFindings].sort(bySeverity),
        },
      })
    } else {
      setRunning(false); setProgress(null)
    }
  }

  // ---- what to display ----
  const activeItem = history.find((h) => h.id === activeId)
  const shown = running
    ? {
        summary: summarize(liveFindings, progress?.root || '', progress?.done || 0, progress?.files_skipped || 0),
        findings: [...liveFindings].sort(bySeverity),
      }
    : activeItem?.result
  const s = shown?.summary
  const visibleFindings = (shown?.findings || []).filter((f) => sevFilter === 'All' || f.severity === sevFilter)

  return (
    <div className="min-h-dvh">
      {/* Top bar */}
      <header className="sticky top-0 z-40 bg-surface-950/80 backdrop-blur-md border-b border-surface-600/40">
        <div className="px-6 h-14 flex items-center gap-2 max-w-[1400px] mx-auto">
          <span className="flex items-center justify-center w-7 h-7 rounded-lg bg-critical/15 text-critical">
            <Bug size={16} />
          </span>
          <span className="font-semibold tracking-tight text-sm">Bug<span className="text-critical">Hunter</span></span>
          <span className="ml-auto text-[11px] text-slate-500 uppercase tracking-widest hidden sm:block num">
            {model || 'Security + Logic'}
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
              placeholder="C:/Users/me/my-project   эсвэл   ./src"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && scan()}
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
            {running ? (
              <button onClick={stop} className="btn-primary justify-center !bg-critical hover:!bg-rose-500">
                <Square size={14} /> Зогсоох
              </button>
            ) : (
              <button onClick={scan} disabled={!path.trim()} className="btn-primary justify-center">
                <Search size={15} /> Шинжлэх
              </button>
            )}
          </div>
          {error && (
            <p className="flex items-center gap-1.5 text-sm text-critical">
              <AlertTriangle size={14} /> {error}
            </p>
          )}
          {running && progress && (
            <ProgressBar done={progress.done} total={progress.total} file={progress.file} />
          )}
        </div>

        {/* History tabs */}
        <HistoryTabs
          history={history}
          activeId={activeId}
          running={running}
          onSelect={(id) => { setActiveId(id); setSevFilter('All') }}
          onNew={() => { setActiveId(null); setError(null) }}
        />

        {/* Summary + findings */}
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

            <div className="card space-y-3">
              <div className="flex items-center justify-between gap-3 flex-wrap">
                <div className="flex items-center gap-2 text-slate-400">
                  <ShieldAlert size={15} />
                  <span className="text-[11px] uppercase tracking-widest">Олдсон асуудлууд</span>
                  {running && <Loader2 size={13} className="animate-spin text-accent" />}
                </div>
                {shown.findings.length > 0 && (
                  <SeverityFilter value={sevFilter} onChange={setSevFilter} counts={s.by_severity} />
                )}
              </div>
              {shown.findings.length === 0 ? (
                <div className="flex flex-col items-center gap-2 py-12 text-slate-400">
                  {running ? (
                    <><Loader2 size={26} className="animate-spin text-accent" /><p className="text-sm">Шинжилж байна…</p></>
                  ) : (
                    <><CheckCircle2 size={28} className="text-low" /><p className="text-sm">Асуудал олдсонгүй — {s.files_scanned} файл цэвэрхэн.</p></>
                  )}
                </div>
              ) : (
                <div className="space-y-2">
                  {visibleFindings.map((f, i) => <FindingCard key={`${f.file}:${f.line}:${i}`} f={f} />)}
                  {visibleFindings.length === 0 && (
                    <p className="text-sm text-slate-500 py-6 text-center">Энэ түвшний асуудал алга.</p>
                  )}
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
        {!s && !running && (
          <div className="card flex flex-col items-center gap-3 py-16 text-slate-400">
            <FileCode size={32} className="text-slate-600" />
            <p className="text-sm">Локал фолдер эсвэл файлын замыг оруулаад <span className="text-accent font-medium">Шинжлэх</span> дарна уу.</p>
            <p className="text-xs text-slate-600 max-w-md text-center">
              Код доторх аюулгүй байдлын эмзэг (injection, secrets, XSS…) болон
              логик алдаа (null deref, race condition, edge case…)-г илрүүлнэ.
            </p>
          </div>
        )}
      </main>
    </div>
  )
}
