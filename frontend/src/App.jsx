import { useState, useRef, useEffect } from 'react'
import {
  Bug, ShieldAlert, Search, FolderSearch, Loader2, FileCode,
  ChevronDown, CheckCircle2, AlertTriangle, Square, Plus, History,
  Globe, Server, Network, Lock, X, Trash2, GitCompare, ScanLine,
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
const SCAN_TYPES = [
  { key: 'code', label: 'Код', icon: FileCode },
  { key: 'web', label: 'Веб', icon: Globe },
  { key: 'host', label: 'Хост', icon: Server },
  { key: 'net', label: 'Сүлжээ', icon: Network },
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

// Scan type of a history item (code scans store mode as all/security/logic)
const TYPE_BY_KEY = Object.fromEntries(SCAN_TYPES.map((t) => [t.key, t]))
function histType(item) {
  return ['web', 'host', 'net'].includes(item.mode) ? item.mode : 'code'
}
function worstSeverity(summary) {
  const s = summary?.by_severity || {}
  return ['Critical', 'High', 'Medium', 'Low'].find((k) => s[k] > 0) || null
}
function relTime(ts) {
  const d = Math.max(0, Date.now() - ts), m = 60000, h = 3600000, day = 86400000
  if (d < m) return 'саяхан'
  if (d < h) return `${Math.floor(d / m)}м`
  if (d < day) return `${Math.floor(d / h)}ц`
  return `${Math.floor(d / day)}ө`
}

// ---- diff between two scans of the same target ----
const findingKey = (f) => `${f.file}|${f.line}|${f.title}`
function diffFindings(curr, prev) {
  const pk = new Set(prev.map(findingKey)), ck = new Set(curr.map(findingKey))
  return {
    added: curr.filter((f) => !pk.has(findingKey(f))).sort(bySeverity),
    removed: prev.filter((f) => !ck.has(findingKey(f))).sort(bySeverity),
  }
}
// Most recent older scan of the same target + same scan type
function previousScanFor(history, item) {
  const idx = history.findIndex((h) => h.id === item.id)
  if (idx === -1) return null
  return history.slice(idx + 1).find((h) => h.path === item.path && histType(h) === histType(item)) || null
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

// ---- host grouping (network / host scans) ----
const hostOf = (file) => { const i = file.indexOf(':'); return i === -1 ? file : file.slice(0, i) }

function groupByHost(findings) {
  const groups = new Map()
  for (const f of findings) {
    const host = hostOf(f.file)
    if (!groups.has(host)) groups.set(host, { host, header: null, items: [] })
    const g = groups.get(host)
    if (!f.file.includes(':')) g.header = f      // the "Live host" summary finding (net)
    else g.items.push(f)
  }
  for (const g of groups.values()) g.items.sort(bySeverity)
  // hosts with worst findings first, then by name
  return [...groups.values()].sort((a, b) => {
    const wa = a.items.length ? SEVERITY[a.items[0].severity].rank : 9
    const wb = b.items.length ? SEVERITY[b.items[0].severity].rank : 9
    return wa - wb || a.host.localeCompare(b.host)
  })
}

function HostGroup({ host, header, items, sevFilter }) {
  const [open, setOpen] = useState(true)
  const shownItems = items.filter((f) => sevFilter === 'All' || f.severity === sevFilter)
  const worstKey = items.length ? items[0].severity : 'Low'
  const osMatch = header?.title.match(/\[(.+?)\]/)
  const os = osMatch ? osMatch[1] : null
  // per-severity counts for this host
  const counts = items.reduce((m, f) => ((m[f.severity] = (m[f.severity] || 0) + 1), m), {})
  return (
    <div className="bg-surface-900/60 border border-surface-700/60 rounded-lg overflow-hidden animate-fade-in">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-surface-800/50 transition-colors"
      >
        <span className={`w-2 h-2 rounded-full shrink-0 ${SEVERITY[worstKey].dot}`} />
        <Server size={14} className="text-slate-400 shrink-0" />
        <span className="num font-medium text-sm">{host}</span>
        {os && <span className="text-[11px] px-2 py-0.5 rounded-full bg-surface-700/60 text-slate-300">{os}</span>}
        <span className="flex items-center gap-1.5 ml-auto shrink-0">
          {['Critical', 'High', 'Medium', 'Low'].map((k) => counts[k] ? (
            <span key={k} className={`text-[11px] num ${SEVERITY[k].text}`}>{counts[k]} {k[0]}</span>
          ) : null)}
          <span className="text-xs text-slate-500 num">{items.length} порт</span>
        </span>
        <ChevronDown size={15} className={`text-slate-500 transition-transform shrink-0 ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div className="px-3 pb-3 space-y-1.5">
          {header && <p className="text-[11px] text-slate-500 px-1 num">{header.description}</p>}
          {items.length === 0 ? (
            <p className="text-xs text-slate-500 px-1 py-1">Нээлттэй порт олдсонгүй.</p>
          ) : shownItems.length === 0 ? (
            <p className="text-xs text-slate-500 px-1 py-1">Энэ түвшний асуудал алга.</p>
          ) : (
            shownItems.map((f, i) => <FindingCard key={`${f.file}:${i}`} f={f} />)
          )}
        </div>
      )}
    </div>
  )
}

function HistoryRow({ h, num, active, onSelect, onDelete }) {
  const t = TYPE_BY_KEY[histType(h)] || TYPE_BY_KEY.code
  const Icon = t.icon
  const total = h.result?.summary?.total_findings ?? 0
  const worst = worstSeverity(h.result?.summary)
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => onSelect(h.id)}
      onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), onSelect(h.id))}
      title={`${h.path}\n${new Date(h.ts).toLocaleString()}`}
      className={`group flex items-center gap-3 px-3 py-2 rounded-lg border cursor-pointer transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/50 ${
        active
          ? 'bg-surface-700/50 border-surface-600'
          : 'bg-surface-900/40 border-surface-700/60 hover:bg-surface-800/50 hover:border-surface-600'
      }`}
    >
      <span className="num text-xs text-slate-500 w-6 text-right shrink-0">{num}.</span>
      <Icon size={15} className="shrink-0 text-slate-400" />
      <div className="flex items-center gap-2 min-w-0 flex-1">
        <span className="num text-sm text-slate-200 truncate">{shortPath(h.path)}</span>
        <span className="text-[10px] uppercase tracking-wider text-slate-600 shrink-0 hidden sm:inline">{t.label}</span>
        {h.partial && <span className="text-medium text-[10px] shrink-0">хагас</span>}
      </div>
      {worst ? (
        <span className={`flex items-center gap-1.5 shrink-0 ${SEVERITY[worst].text}`}>
          <span className={`w-1.5 h-1.5 rounded-full ${SEVERITY[worst].dot}`} />
          <span className="num text-xs">{total}</span>
        </span>
      ) : (
        <CheckCircle2 size={14} className="text-low shrink-0" />
      )}
      <span className="num text-[11px] text-slate-500 w-12 text-right shrink-0">{relTime(h.ts)}</span>
      <button
        onClick={(e) => { e.stopPropagation(); onDelete(h.id) }}
        aria-label="Устгах"
        className="p-1 rounded text-slate-600 opacity-0 group-hover:opacity-100 hover:text-critical hover:bg-surface-800 transition-opacity shrink-0"
      >
        <X size={14} />
      </button>
    </div>
  )
}

const HIST_FILTERS = [['all', 'Бүгд'], ['code', 'Код'], ['web', 'Веб'], ['host', 'Хост'], ['net', 'Сүлжээ']]

function HistoryPanel({ history, activeId, filter, onFilter, onSelect, onDelete, onClear, onNew }) {
  const [confirmClear, setConfirmClear] = useState(false)
  const filtered = filter === 'all' ? history : history.filter((h) => histType(h) === filter)
  return (
    <div className="card space-y-3">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2 text-slate-400">
          <History size={15} />
          <span className="text-[11px] uppercase tracking-widest">Скан түүх</span>
          <span className="num text-[11px] text-slate-600">{history.length}</span>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={onNew} className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-lg bg-accent/15 text-accent hover:bg-accent/25 transition-colors">
            <Plus size={13} /> Шинэ скан
          </button>
          {history.length > 0 && (
            confirmClear ? (
              <span className="flex items-center gap-2 text-[11px]">
                <span className="text-slate-300">Бүгдийг ({history.length}) устгах уу?</span>
                <button
                  onClick={() => { onClear(); setConfirmClear(false) }}
                  className="font-medium text-critical hover:underline"
                >
                  Тийм, устга
                </button>
                <button
                  onClick={() => setConfirmClear(false)}
                  className="text-slate-400 hover:text-slate-200"
                >
                  Болих
                </button>
              </span>
            ) : (
              <button
                onClick={() => setConfirmClear(true)}
                className="flex items-center gap-1 text-[11px] text-slate-500 hover:text-critical transition-colors"
                title="Бүх түүхийг цэвэрлэх"
              >
                <Trash2 size={12} /> Цэвэрлэх
              </button>
            )
          )}
        </div>
      </div>

      {/* Type filter */}
      <div className="flex gap-1 flex-wrap">
        {HIST_FILTERS.map(([k, label]) => {
          const count = k === 'all' ? history.length : history.filter((h) => histType(h) === k).length
          const active = filter === k
          return (
            <button
              key={k}
              onClick={() => onFilter(k)}
              className={`text-[11px] px-2.5 py-1 rounded-full border transition-colors ${
                active ? 'bg-accent/15 text-accent border-accent/30'
                       : 'border-surface-700/60 text-slate-400 hover:text-slate-200'
              }`}
            >
              {label}{count ? ` ${count}` : ''}
            </button>
          )
        })}
      </div>

      {filtered.length === 0 ? (
        <div className="flex flex-col items-center gap-2 py-10 text-slate-500">
          <History size={26} className="text-slate-600" />
          <p className="text-sm">{history.length === 0 ? 'Түүх хоосон байна.' : 'Энэ төрлийн скан алга.'}</p>
        </div>
      ) : (
        <div className="space-y-1 max-h-[28rem] overflow-y-auto pr-0.5">
          {filtered.map((h, i) => (
            <HistoryRow key={h.id} h={h} num={i + 1} active={activeId === h.id} onSelect={onSelect} onDelete={onDelete} />
          ))}
        </div>
      )}
    </div>
  )
}

function DiffFindingRow({ f, kind }) {
  const sev = SEVERITY[f.severity]
  return (
    <div className="flex items-center gap-2 text-xs py-0.5">
      <span className={`shrink-0 num ${kind === 'added' ? 'text-critical' : 'text-low'}`}>{kind === 'added' ? '+' : '−'}</span>
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${sev.dot}`} />
      <span className="text-slate-300 truncate flex-1">{f.title}</span>
      <span className="num text-slate-600 shrink-0 truncate max-w-[180px]">{f.file}{f.line ? `:${f.line}` : ''}</span>
    </div>
  )
}

function DiffBanner({ diff, prev }) {
  const added = diff.added.length, removed = diff.removed.length
  if (!added && !removed) {
    return (
      <div className="card flex items-center gap-2 text-sm text-low">
        <GitCompare size={15} /> Өмнөх скантай ижил — өөрчлөлт алга ({relTime(prev.ts)} өмнө хийсэнтэй харьцуулав).
      </div>
    )
  }
  return (
    <div className="card space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <GitCompare size={15} className="text-accent" />
        <span className="text-[11px] uppercase tracking-widest text-slate-400">Өөрчлөлт</span>
        <span className="text-[11px] text-slate-500 num">{relTime(prev.ts)} өмнөх скантай харьцуулав</span>
        <span className="ml-auto flex items-center gap-3 text-sm">
          {added > 0 && <span className="text-critical num">+{added} шинэ</span>}
          {removed > 0 && <span className="text-low num">−{removed} засагдсан</span>}
        </span>
      </div>
      {added > 0 && (
        <div>
          <p className="text-[11px] text-critical mb-1">Шинээр гарсан</p>
          <div className="space-y-0.5">{diff.added.slice(0, 12).map((f, i) => <DiffFindingRow key={i} f={f} kind="added" />)}
            {added > 12 && <p className="text-[11px] text-slate-600">…+{added - 12} бусад</p>}</div>
        </div>
      )}
      {removed > 0 && (
        <div>
          <p className="text-[11px] text-low mb-1">Засагдсан / алга болсон</p>
          <div className="space-y-0.5">{diff.removed.slice(0, 12).map((f, i) => <DiffFindingRow key={i} f={f} kind="removed" />)}
            {removed > 12 && <p className="text-[11px] text-slate-600">…+{removed - 12} бусад</p>}</div>
        </div>
      )}
    </div>
  )
}

export default function App() {
  const [scanType, setScanType] = useState('code')   // code | web | host
  const [path, setPath] = useState('')
  const [target, setTarget] = useState('')           // url (web) / host (host) / cidr (net)
  const [aiWeb, setAiWeb] = useState(false)
  const [authorized, setAuthorized] = useState(false)
  const [quick, setQuick] = useState(false)
  const [showAuth, setShowAuth] = useState(false)
  const [cookie, setCookie] = useState('')
  const [authHeader, setAuthHeader] = useState('')   // "Key: Value"
  const [basic, setBasic] = useState('')             // "user:pass"
  const [browser, setBrowser] = useState('none')     // reuse local browser session
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
  const [view, setView] = useState('scan')           // scan | history
  const [histFilter, setHistFilter] = useState('all')
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

  function deleteScan(id) {
    const next = history.filter((h) => h.id !== id)
    persist(next)
    if (activeId === id) setActiveId(null)
  }

  function clearHistory() {
    persist([])
    setActiveId(null)
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

  // Web / host scans are quick POST requests (no streaming).
  async function runPostScan() {
    const t = target.trim()
    if (!t || running) return
    closeStream()
    setRunning(true); setError(null); setLiveFindings([]); setActiveId(null); setSevFilter('All'); setProgress(null)
    const endpoint = `/api/${scanType}`   // /api/web | /api/host | /api/net
    let body
    if (scanType === 'web') {
      const headers = {}
      if (authHeader.includes(':')) {
        const i = authHeader.indexOf(':')
        headers[authHeader.slice(0, i).trim()] = authHeader.slice(i + 1).trim()
      }
      body = {
        url: t, ai: aiWeb,
        cookie: cookie.trim() || null,
        basic: basic.trim() || null,
        headers: Object.keys(headers).length ? headers : null,
        browser: browser !== 'none' ? browser : null,
      }
    } else if (scanType === 'net') {
      body = { cidr: t, authorized, quick }
    } else {
      body = { host: t, authorized }
    }
    try {
      const r = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!r.ok) {
        let detail = `Алдаа (${r.status})`
        try { detail = (await r.json()).detail || detail } catch { /* keep */ }
        throw new Error(detail)
      }
      const result = await r.json()
      finishScan({
        id: `${Date.now()}-${Math.round(Math.random() * 1e6)}`,
        path: t, mode: scanType, ts: Date.now(), result,
      })
    } catch (e) {
      setError(e.message || 'Backend ажиллахгүй байна (port 8000)')
      setRunning(false)
    }
  }

  function start() {
    if (scanType === 'code') scan()
    else runPostScan()
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
  const shownType = running ? scanType : (activeItem?.mode || 'code')
  const grouped = shownType === 'net' || shownType === 'host'
  const visibleFindings = (shown?.findings || []).filter((f) => sevFilter === 'All' || f.severity === sevFilter)
  // Host-grouped view for network/host scans
  const hostGroups = grouped ? groupByHost(shown?.findings || []) : []
  const visibleGroups = sevFilter === 'All'
    ? hostGroups
    : hostGroups.filter((g) => g.items.some((f) => f.severity === sevFilter))
  const liveHosts = grouped ? hostGroups.length : 0
  // Change diff: compare the shown finished scan with the previous scan of the same target
  const prevScan = activeItem && !running ? previousScanFor(history, activeItem) : null
  const diff = prevScan ? diffFindings(activeItem.result.findings, prevScan.result.findings) : null

  return (
    <div className="min-h-dvh">
      {/* Top bar */}
      <header className="sticky top-0 z-40 bg-surface-950/80 backdrop-blur-md border-b border-surface-600/40">
        <div className="px-6 h-14 flex items-center gap-2 max-w-[1400px] mx-auto">
          <span className="flex items-center justify-center w-7 h-7 rounded-lg bg-critical/15 text-critical">
            <Bug size={16} />
          </span>
          <span className="font-semibold tracking-tight text-sm">Bug<span className="text-critical">Hunter</span></span>
          <nav className="ml-4 flex gap-1 text-xs">
            {[['scan', 'Скан', ScanLine], ['history', 'Түүх', History]].map(([k, label, Icon]) => (
              <button
                key={k}
                onClick={() => setView(k)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-colors ${
                  view === k ? 'bg-surface-700/60 text-slate-100' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Icon size={14} /> {label}
                {k === 'history' && history.length > 0 && (
                  <span className="num text-[10px] px-1.5 rounded-full bg-surface-700 text-slate-300">{history.length}</span>
                )}
              </button>
            ))}
          </nav>
          <span className="ml-auto text-[11px] text-slate-500 uppercase tracking-widest hidden sm:block num">
            {model || 'Security + Logic'}
          </span>
        </div>
      </header>

      <main className="p-6 max-w-[1400px] mx-auto space-y-6 animate-fade-in">
        {/* Scan controls (scan view only) */}
        {view === 'scan' && (
        <div className="card space-y-3">
          {/* Scan-type selector */}
          <div className="flex gap-1 bg-surface-900 border border-surface-600/60 rounded-lg p-1 w-fit">
            {SCAN_TYPES.map((t) => {
              const Icon = t.icon
              return (
                <button
                  key={t.key}
                  onClick={() => { if (!running) { setScanType(t.key); setError(null) } }}
                  disabled={running}
                  className={`flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded transition-colors disabled:opacity-50 ${
                    scanType === t.key ? 'bg-accent text-white' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Icon size={13} /> {t.label}
                </button>
              )
            })}
          </div>

          {scanType === 'code' ? (
            <div className="flex flex-col md:flex-row gap-2">
              <input
                className="input flex-1 num"
                placeholder="C:/Users/me/my-project   эсвэл   ./src"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && start()}
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
                <button onClick={start} disabled={!path.trim()} className="btn-primary justify-center">
                  <Search size={15} /> Шинжлэх
                </button>
              )}
            </div>
          ) : (
            <div className="space-y-2">
              <div className="flex flex-col md:flex-row gap-2">
                <input
                  className="input flex-1 num"
                  placeholder={
                    scanType === 'web' ? 'https://example.com'
                    : scanType === 'net' ? '192.168.1.0/24'
                    : '127.0.0.1   эсвэл   192.168.1.10'
                  }
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && start()}
                  aria-label="Target"
                />
                <button onClick={start} disabled={running || !target.trim()} className="btn-primary justify-center">
                  {running ? <Loader2 size={15} className="animate-spin" /> : <Search size={15} />}
                  {running ? 'Шинжилж байна…' : 'Шинжлэх'}
                </button>
              </div>

              {scanType === 'web' && (
                <>
                  <div className="flex items-center gap-3 flex-wrap">
                    <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer">
                      <input type="checkbox" checked={aiWeb} onChange={(e) => setAiWeb(e.target.checked)} />
                      AI нэмэлт шинжилгээ
                    </label>
                    <button
                      onClick={() => setShowAuth(!showAuth)}
                      className="flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200"
                    >
                      <Lock size={12} /> Нэвтрэлт (authenticated scan)
                      <ChevronDown size={13} className={`transition-transform ${showAuth ? 'rotate-180' : ''}`} />
                    </button>
                  </div>
                  {showAuth && (
                    <div className="space-y-2 pt-1">
                      <div className="flex items-center gap-2">
                        <span className="text-[11px] text-slate-400 shrink-0">Браузерын session ашиглах:</span>
                        <select className="input text-xs py-1" value={browser}
                          onChange={(e) => setBrowser(e.target.value)} aria-label="Browser session">
                          <option value="none">— гар аргаар оруулна —</option>
                          <option value="auto">Аль ч браузер (auto)</option>
                          <option value="chrome">Chrome</option>
                          <option value="edge">Edge</option>
                          <option value="firefox">Firefox</option>
                          <option value="brave">Brave</option>
                          <option value="opera">Opera</option>
                        </select>
                      </div>
                      <p className="text-[11px] text-slate-600">
                        Браузер сонгвол тухайн сайтад нэвтэрсэн cookie-г автоматаар авна (гар аргаар хуулахгүй).
                        Орчин үеийн Chrome/Edge нь cookie-г шифрлэдэг тул заримдаа Firefox илүү найдвартай.
                      </p>
                      <div className="grid sm:grid-cols-3 gap-2">
                        <input className="input num text-xs" placeholder="эсвэл Cookie: session=abc"
                          value={cookie} onChange={(e) => setCookie(e.target.value)} aria-label="Cookie" />
                        <input className="input num text-xs" placeholder="Header: Authorization: Bearer …"
                          value={authHeader} onChange={(e) => setAuthHeader(e.target.value)} aria-label="Header" />
                        <input className="input num text-xs" placeholder="Basic: user:pass"
                          value={basic} onChange={(e) => setBasic(e.target.value)} aria-label="Basic auth" />
                      </div>
                    </div>
                  )}
                </>
              )}
              {scanType === 'host' && (
                <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer w-fit">
                  <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
                  <span>Би энэ target-г скан хийх <span className="text-high">зөвшөөрөлтэй</span> (public хаягт шаардлагатай)</span>
                </label>
              )}
              {scanType === 'net' && (
                <div className="flex items-center gap-3 flex-wrap">
                  <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer">
                    <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
                    <span><span className="text-high">Зөвшөөрөлтэй</span> (public range-д шаардлагатай)</span>
                  </label>
                  <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer">
                    <input type="checkbox" checked={quick} onChange={(e) => setQuick(e.target.checked)} />
                    Хурдан (зөвхөн түгээмэл портууд)
                  </label>
                </div>
              )}
              <p className="text-[11px] text-slate-600">
                {scanType === 'web'
                  ? 'Зөвхөн өөрийн / зөвшөөрөлтэй сайт. Довтлох payload явуулахгүй — header/cookie/TLS/мэдээлэл задралт. Нэвтрэлт оруулбал нэвтэрсэн төлөвт гүн шалгана.'
                  : scanType === 'net'
                  ? 'CIDR range доторх амьд host, нээлттэй порт, OS таамаг (banner+TTL heuristic). Private default; public бол зөвшөөрөл. Exploit хийхгүй.'
                  : 'Зөвхөн өөрийн / зөвшөөрөлтэй host. Стандарт TCP порт скан (exploit хийхгүй). Private/localhost default.'}
              </p>
            </div>
          )}

          {error && (
            <p className="flex items-center gap-1.5 text-sm text-critical">
              <AlertTriangle size={14} /> {error}
            </p>
          )}
          {running && scanType === 'code' && progress && (
            <ProgressBar done={progress.done} total={progress.total} file={progress.file} />
          )}
        </div>
        )}

        {/* History panel (history view only) */}
        {view === 'history' && (
          <HistoryPanel
            history={history}
            activeId={activeId}
            filter={histFilter}
            onFilter={setHistFilter}
            onSelect={(id) => { setActiveId(id); setSevFilter('All') }}
            onNew={() => { setView('scan'); setActiveId(null); setError(null) }}
            onDelete={deleteScan}
            onClear={clearHistory}
          />
        )}

        {/* Change diff vs previous scan of the same target */}
        {diff && <DiffBanner diff={diff} prev={prevScan} />}

        {/* Summary + findings */}
        {s && (
          <>
            <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
              <StatCard label="Нийт олдсон" value={s.total_findings} tone={s.total_findings ? 'text-slate-100' : 'text-low'} />
              <StatCard label="Critical" value={s.by_severity.Critical} tone={s.by_severity.Critical ? 'text-critical' : 'text-slate-500'} />
              <StatCard label="High" value={s.by_severity.High} tone={s.by_severity.High ? 'text-high' : 'text-slate-500'} />
              <StatCard label="Medium" value={s.by_severity.Medium} tone={s.by_severity.Medium ? 'text-medium' : 'text-slate-500'} />
              {shownType === 'net' ? (
                <StatCard label="Амьд host" value={liveHosts} tone={liveHosts ? 'text-slate-100' : 'text-slate-500'} />
              ) : (
                <StatCard label="Аюулгүй / Логик" value={`${s.by_category.Security} / ${s.by_category.Logic}`} />
              )}
              <StatCard
                label={shownType === 'net' ? 'Host шалгасан' : shownType === 'host' ? 'Порт шалгасан' : 'Файл'}
                value={`${s.files_scanned}`}
                tone="text-slate-300"
              />
            </div>

            <div className="card space-y-3">
              <div className="flex items-center justify-between gap-3 flex-wrap">
                <div className="flex items-center gap-2 text-slate-400">
                  <ShieldAlert size={15} />
                  <span className="text-[11px] uppercase tracking-widest">
                    {shownType === 'net' ? 'Олдсон host-ууд' : 'Олдсон асуудлууд'}
                  </span>
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
                    <><CheckCircle2 size={28} className="text-low" /><p className="text-sm">
                      {shownType === 'net' ? 'Амьд host олдсонгүй.'
                       : shownType === 'host' ? 'Нээлттэй порт олдсонгүй.'
                       : `Асуудал олдсонгүй — ${s.files_scanned} файл цэвэрхэн.`}
                    </p></>
                  )}
                </div>
              ) : grouped ? (
                <div className="space-y-2">
                  {visibleGroups.map((g) => (
                    <HostGroup key={g.host} host={g.host} header={g.header} items={g.items} sevFilter={sevFilter} />
                  ))}
                  {visibleGroups.length === 0 && (
                    <p className="text-sm text-slate-500 py-6 text-center">Энэ түвшний асуудалтай host алга.</p>
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
        {view === 'scan' && !s && !running && (
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
