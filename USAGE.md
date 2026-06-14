# BugHunter — Хэрэглэх гарын авлага

Claude эсвэл локал Ollama загвараар ажилладаг **код доторх аюулгүй байдлын эмзэг
байдал (security) болон логик алдаа (logic bug)** ологч. Web dashboard эсвэл
CLI-аар ашиглана.

---

## 1. Юу шаардлагатай вэ

| Зүйл | Төлөв | Тэмдэглэл |
|------|-------|-----------|
| Python 3.11+ | ✅ суусан | Backend ажиллуулна |
| Node.js 18+ | ✅ суусан | Frontend (Vite) ажиллуулна |
| Ollama | ✅ суусан | Локал, үнэгүй горим |
| `qwen2.5-coder:14b` загвар | ✅ татсан (9GB) | Локал шинжилгээний загвар |
| Anthropic API key | ⛔ заавал биш | Зөвхөн cloud Claude горимд хэрэгтэй |

Энэ систем **2 горимд** ажиллана:
- **Ollama (локал, үнэгүй)** — одоо тохируулсан үндсэн горим. API key хэрэггүй.
- **Anthropic (cloud Claude)** — илүү чанартай, гэхдээ API key + төлбөр шаардана.

---

## 2. Хурдан эхлэх (3 терминал)

> ⚠️ **Windows PowerShell дээр `ollama` олдохгүй бол** эхлээд PATH-г шинэчил:
> ```powershell
> $env:Path = [System.Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path','User')
> ```

### Терминал 1 — Ollama (ихэвчлэн background-д автоматаар ажилладаг)
Ollama суулгасны дараа service автоматаар асдаг. Шалгах:
```powershell
ollama list                      # татсан загваруудыг харах
# Хэрэв service асаагүй бол:
ollama serve
```

### Терминал 2 — Backend (API, порт 8000)
```powershell
cd "C:\Users\my tech\Claude\BugHunter\backend"
python -m uvicorn bughunter.server:app --port 8000
```
Шалгах: http://localhost:8000/health →
`{"status":"ok","provider":"ollama","model":"ollama:qwen2.5-coder:14b"}`

### Терминал 3 — Frontend (UI, порт 5173)
```powershell
cd "C:\Users\my tech\Claude\BugHunter\frontend"
npm install        # анх удаа л хийнэ
npm run dev
```
Нээх: **http://localhost:5173**

---

## 3. Web UI-аар ашиглах

1. http://localhost:5173 нээ.
2. Дээд талын талбарт **лок зам** оруул, жишээ нь:
   - Фолдер: `C:/Users/my tech/Claude/Trading/backend`
   - Нэг файл: `C:/Users/my tech/Claude/Trading/backend/main.py`
   - 💡 **Forward slash (`/`) ашигла** — backslash асуудал үүсгэж магадгүй.
3. Шинжлэх төрөл сонго:
   - **Бүгд** — security + logic (default)
   - **Аюулгүй байдал** — зөвхөн security
   - **Логик алдаа** — зөвхөн logic
4. Файлын дээд тоо (default 40) тохируул.
5. **Шинжлэх** дар. Үр дүн **шууд урсаж** харагдана:
   - Дээд талд **progress bar** (хийгдсэн/нийт файл, %) + одоо шинжилж буй файл.
   - Олдсон асуудлууд бэлэн болмогц нэг нэгээр нэмэгдэнэ (бүх скан дуустал хүлээхгүй).
   - **Зогсоох** товч скан дундуур таслаад, олдсон хэсгийг хадгална.
6. **Severity filter** (Бүгд / Critical / High / Medium / Low) chip-ээр шүүнэ.
7. **Түүх (history):** дууссан скануудыг хөтөч дотор (`localStorage`, ~20 хүртэл)
   хадгалж, дээд талын таб-аар хооронд нь сэлгэнэ. "Шинэ" дарж шинэ скан эхлүүлнэ.

---

## 4. CLI-аар ашиглах (терминалаас)

```powershell
cd "C:\Users\my tech\Claude\BugHunter\backend"

# Бүх алдаа
python -m bughunter.cli scan "C:/Users/my tech/Claude/Trading/backend"

# Зөвхөн security
python -m bughunter.cli scan <зам> --security-only

# Зөвхөн logic
python -m bughunter.cli scan <зам> --logic-only

# Файлын тоо хязгаарлах + JSON-руу хадгалах
python -m bughunter.cli scan <зам> --max-files 20 --json findings.json
```

> CLI нь Critical/High алдаа олвол **exit code 1** буцаана — CI / pre-commit hook-д тохиромжтой.

**False positive багасгах (`--verify`):** олдсон алдаа бүрийг дахин шалгаж, эргэлзээтэйг
нь хаядаг хоёр дахь дамжуулалт. Чанар нэмэгдэх ч хугацаа/зардал ~2 дахин болно. Бүх
скан дээр асаах бол `.env`-д `SCAN_VERIFY=1`.
```powershell
python -m bughunter.cli scan <зам> --verify
```

---

## 4.5 Веб ба Хост скан (шинэ)

> ⚠️ **Зөвхөн өөрийн эзэмшдэг эсвэл бичгээр зөвшөөрөл авсан target дээр ажиллуул.**
> Зөвшөөрөлгүй host/сайт скан хийх нь ихэнх улсад **хууль бус**.

### Веб скан (`web`) — довтлох биш, байдал шалгах
Энгийн HTTP хүсэлт (браузертай адил) явуулж, сервер юу буцаахыг шинжилнэ: security
header (HSTS, CSP, X-Frame-Options…), cookie флаг (Secure/HttpOnly/SameSite), TLS,
сервер banner задралт, permissive CORS. **Payload, fuzzing, exploit явуулахгүй.**
```powershell
python -m bughunter.cli web https://example.com
python -m bughunter.cli web https://miний-сайт.mn --ai   # LLM нэмэлт шинжилгээ
```

### Хост скан (`host`) — TCP порт/service скан
Стандарт TCP connect скан (`nmap -sT`-тэй адил) + banner унших. **Exploit хийхгүй.**
- **Private/localhost** (127.0.0.1, 192.168.x, 10.x…) — шууд зөвшөөрөгдөнө.
- **Public хаяг** — `--authorized` тугтайгаар л ажиллана (зөвшөөрөлтэйгөө баталгаажуулна).
```powershell
python -m bughunter.cli host 127.0.0.1
python -m bughunter.cli host 192.168.1.10 --ports 22,80,443,3306
python -m bughunter.cli host миний-сервер.mn --authorized
```
Нээлттэй эрсдэлтэй порт (Telnet, ил DB, Docker API, RDP…)-ыг severity-тэйгээр илрүүлнэ.

### Web UI-аас
Дээд талын **Код / Веб / Хост** таб сонгоод target оруулна. Хост дээр public бол
"зөвшөөрөлтэй" чек тавина. Үр дүн ижил байдлаар severity-ээр харагдана.

---

## 5. Үр дүнг ойлгох

**Severity (ноцтой байдал):**
| Түвшин | Утга |
|--------|------|
| 🔴 Critical | Ашиглагдахуйц / өгөгдөл алдагдах |
| 🟠 High | Ноцтой алдаа |
| 🟡 Medium | Засах нь зүйтэй |
| 🔵 Low | Бага зэргийн |

**Category:** `Security` (injection, XSS, secrets, weak crypto…) эсвэл `Logic`
(null deref, off-by-one, race condition, edge case…).

Findings бүр: файл, мөрийн дугаар, тайлбар, **бодит засварын зөвлөмж**, болон
confidence (High/Medium/Low) агуулна.

---

## 6. Тохиргоо (`backend/.env`)

```ini
# Аль backend ашиглах: "ollama" (локал) эсвэл "anthropic" (cloud)
PROVIDER=ollama

# Хэдэн файлыг зэрэг шинжлэх (default 5). Cloud (Anthropic) дээр өндөр тоо
# хурдасгана; локал ганц Ollama загвар дээр хүсэлтүүд GPU дээр дараалдаг тул
# өсгөх нь хурд нэмэхгүй (мөн том загвар OOM болж магадгүй) — даруухан байлга.
# Локал параллель болгох бол Ollama-ийн өөрийн OLLAMA_NUM_PARALLEL-ийг өсгө.
# SCAN_CONCURRENCY=5

# --- Ollama (локал, үнэгүй) ---
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=qwen2.5-coder:14b
OLLAMA_NUM_CTX=16384

# --- Anthropic (cloud Claude) — PROVIDER=anthropic үед ---
# ANTHROPIC_API_KEY=sk-ant-...
# ANTHROPIC_MODEL=claude-opus-4-8
```

**Cloud Claude рүү шилжих:** `PROVIDER=anthropic` болгож, `ANTHROPIC_API_KEY`
оруулаад backend-г дахин асаа.

---

## 7. Гүйцэтгэл ба загвар сонгох

Энэ машин: **RTX 5060 (8GB VRAM), 31GB RAM**.

| Загвар | Хэмжээ | Хурд | Тэмдэглэл |
|--------|--------|------|-----------|
| `qwen2.5-coder:14b` | ~9GB | ~85 сек/файл | 8GB VRAM-д бүрэн багтахгүй → хэсэг нь CPU дээр. Чанар сайн (одоогийн) |
| `qwen2.5-coder:7b` | ~4.7GB | мэдэгдэхүйц хурдан | 8GB-д бүрэн багтана. Чанар арай бага |
| Cloud `claude-opus-4-8` | — | хурдан, хамгийн чанартай | API key + төлбөр |

**Хурдан болгох (7b руу шилжих):**
```powershell
ollama pull qwen2.5-coder:7b
# дараа нь backend/.env дотор: OLLAMA_MODEL=qwen2.5-coder:7b
# backend-г дахин асаа
```

> Олон файл зэрэг скан хийхэд concurrency=5 учир нийт хугацаа богиносдог
> (`analyzer.py` доторх semaphore-оор удирдагдана).

---

## 8. Файлын хязгаарлалт (scanner)

- Дэмждэг өргөтгөл: `.py .js .ts .tsx .go .rs .java .rb .php .cs .c .cpp .sql .sh` гэх мэт.
- Алгасдаг фолдер: `node_modules .git venv __pycache__ dist build` гэх мэт.
- Файлын дээд хэмжээ: **80KB** буюу **1500 мөр** (түүнээс том файл алгасагдана).

---

## 9. Алдаа засах (Troubleshooting)

| Шинж тэмдэг | Шалтгаан / Шийдэл |
|-------------|-------------------|
| `/health` → connection refused | Backend асаагүй. Терминал 2-г ажиллуул |
| Scan → "Cannot reach Ollama" | Ollama service асаагүй → `ollama serve`; эсвэл загвар татаагүй → `ollama pull qwen2.5-coder:14b` |
| Scan → "model not found" | `ollama pull <загвар нэр>` |
| HTTP 422 / "Invalid \escape" | Зам дээр backslash. **Forward slash (`/`) ашигла** |
| Эхний scan маш удаан | Загвар санах ойд анх удаа ачаалагдаж байна — дараагийнх хурдан |
| `ollama` олдохгүй (PowerShell) | Дээрх PATH-шинэчлэх командыг ажиллуул |
| ANTHROPIC_API_KEY алдаа | `PROVIDER=ollama` эсэхийг шалга (cloud горимд л key хэрэгтэй) |

---

## 10. Архитектур (товч)

```
backend/bughunter/
  scanner.py    # лок замаас source файл цуглуулна (ignore, хэмжээ хязгаар)
  analyzer.py   # файл бүрийг загварт явуулж бүтэцлэгдсэн Finding[] цуглуулна (concurrent)
  provider.py   # LLM backend switch: Anthropic (cloud) | Ollama (локал)
  schemas.py    # Finding/ScanResult загвар + JSON schema
  webscan.py    # веб байдал шалгах (header/cookie/TLS) — intrusive биш
  hostscan.py   # TCP порт/service скан — зөвшөөрлийн хаалгатай
  cli.py        # `python -m bughunter.cli {scan|web|host} <target>` — өнгөт тайлан
  server.py     # FastAPI: POST /scan, GET /scan/stream (SSE), POST /web, POST /host, GET /health
frontend/       # React + Vite + Tailwind dashboard (/api -> :8000 proxy), Код/Веб/Хост таб
```

`analyzer.py`-д `scan_path` (нэг удаагийн үр дүн, CLI/`POST /scan`-д) болон
`scan_stream` (event-ээр урсгах, `GET /scan/stream`-д) гэсэн хоёр зам байна. UI нь
`EventSource`-оор stream-г сонсож progress/finding-г шууд харуулна.

Хоёр горим хоёулаа JSON schema-аар хязгаарлагдсан хариу буцаадаг тул markdown
задлах эсвэл JSON засах логик хэрэггүй.

---

## 11. Git ажиллах урсгал (branch → push → PR)

Шинэ өөрчлөлтийг үндсэн салбар (`main`) дээр шууд хийхгүйгээр тусдаа **салбар
(branch)** дээр хийгээд, дараа нь нэгтгэдэг. Энэ нь `main`-г үргэлж тогтвортой
байлгаж, өөрчлөлтийг хянах боломж олгодог.

### Үндсэн алхмууд

```powershell
cd "C:\Users\my tech\Claude\BugHunter"

# 1. Шинэ салбар үүсгэж шилжих
git checkout -b feature/миний-өөрчлөлт

# 2. Код засаад, өөрчлөлтөө commit хийх
git add -A
git commit -m "Юу хийсэн тухай тайлбар"

# 3. Салбараа GitHub руу илгээх (push)
git push -u origin feature/миний-өөрчлөлт
```

### PR (Pull Request) гэж юу вэ?

**PR = "Энэ салбар дээрх өөрчлөлтийг `main` руу нэгтгэхийг хүсэж байна" гэсэн
хүсэлт.** Шууд нэгтгэхийн оронд PR ашиглавал: өөрчлөлтийг (нэмэгдсэн/устсан мөр)
харах, хянах, түүх үлдээх боломжтой. Ганцаараа ажиллаж байгаа бол **заавал биш** —
гэхдээ цэвэр, аюулгүй арга.

**PR үүсгэх (вэбээр, хамгийн хялбар):** push хийсний дараа гарч ирэх линкийг нээ:
```
https://github.com/<хэрэглэгч>/<repo>/pull/new/<салбарын-нэр>
```
`base: main` ← `compare: <салбар>` сонгоод **"Create pull request"** дар. Дараа нь
**"Merge"** дарвал өөрчлөлт `main`-д орно.

**PR үүсгэх (`gh` CLI-аар):** `winget install GitHub.cli` → `gh auth login` →
```powershell
gh pr create --base main --head <салбарын-нэр> --fill
```
> `--fill` нь commit-ийн гарчиг/тайлбарыг автоматаар PR-д бөглөнө.
