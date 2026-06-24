package main

import (
	"archive/zip"
	"bufio"
	"encoding/csv"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	listen := getenv("LISTEN_ADDR", ":8090")
	dashAddr := getenv("DASH_ADDR", ":8091")
	upstream := getenv("UPSTREAM_URL", "http://clamav-rest-api:8080")
	clamdAddr := getenv("CLAMD_ADDR", "clamav:3310")
	maxConc := getint("MAX_CONCURRENT", 10)
	scanTO := getdur("SCAN_TIMEOUT", 130*time.Second)
	logPath := getenv("LOG_PATH", "/data/scans.log")

	g := &gateway{
		upstream:  upstream,
		clamdAddr: clamdAddr,
		sem:       make(chan struct{}, maxConc),
		maxConc:   maxConc,
		viruses:   map[string]int64{},
		client:    &http.Client{Timeout: scanTO},
		log:       log,
		startedAt: time.Now(),
		logPath:   logPath,
	}

	if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640); err != nil {
		log.Warn("cannot open scan journal", "path", logPath, "err", err)
	} else {
		g.logFile = f
		defer f.Close()
	}

	go g.dbLoop()

	// API — только скан. nginx проксирует сюда.
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("POST /api/v1/scan", g.handleScan)

	// Дашборд — мониторинг, статистика, отчёты. Docker выставляет наружу.
	dashMux := http.NewServeMux()
	dashMux.HandleFunc("GET /", g.handleDashboard)
	dashMux.HandleFunc("GET /stats", g.handleStats)
	dashMux.HandleFunc("GET /report", g.handleReport)
	dashMux.HandleFunc("GET /healthz", g.handleHealthz)

	apiSrv := &http.Server{
		Addr:              listen,
		Handler:           apiMux,
		ReadTimeout:       scanTO + 30*time.Second,
		WriteTimeout:      scanTO + 30*time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	dashSrv := &http.Server{
		Addr:              dashAddr,
		Handler:           dashMux,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Info("dashboard up", "addr", dashAddr)
		if err := dashSrv.ListenAndServe(); err != nil {
			log.Error("dashboard server", "err", err)
			os.Exit(1)
		}
	}()

	log.Info("api up", "listen", listen, "upstream", upstream,
		"clamd", clamdAddr, "max_concurrent", maxConc)
	if err := apiSrv.ListenAndServe(); err != nil {
		log.Error("api server", "err", err)
		os.Exit(1)
	}
}

type activity struct {
	Time     string   `json:"time"`
	IP       string   `json:"ip"`
	File     string   `json:"file"`
	Infected bool     `json:"infected"`
	Viruses  []string `json:"viruses"`
}

type gateway struct {
	upstream  string
	clamdAddr string
	client    *http.Client
	sem       chan struct{}
	maxConc   int
	log       *slog.Logger
	startedAt time.Time

	scanned  int64
	infected int64
	errors   int64
	active   int64
	waiting  int64

	mu      sync.Mutex
	viruses map[string]int64
	recent  []activity

	logPath string
	logMu   sync.Mutex
	logFile *os.File

	dbMu      sync.RWMutex
	dbEngine  string
	dbVersion string
	dbDate    string
	dbBuilt   time.Time
	dbBuiltOK bool
	dbChecked time.Time
	dbErr     string
}

type upstreamResp struct {
	Success bool `json:"success"`
	Data    struct {
		Result []struct {
			Name       string   `json:"name"`
			IsInfected bool     `json:"is_infected"`
			Viruses    []string `json:"viruses"`
		} `json:"result"`
	} `json:"data"`
}

func (g *gateway) handleScan(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)

	atomic.AddInt64(&g.waiting, 1)
	select {
	case g.sem <- struct{}{}:
	case <-r.Context().Done():
		atomic.AddInt64(&g.waiting, -1)
		return
	}
	atomic.AddInt64(&g.waiting, -1)
	atomic.AddInt64(&g.active, 1)
	defer func() {
		<-g.sem
		atomic.AddInt64(&g.active, -1)
	}()

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		g.upstream+"/api/v1/scan", r.Body)
	if err != nil {
		atomic.AddInt64(&g.errors, 1)
		http.Error(w, "build upstream request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", r.Header.Get("Content-Type"))

	resp, err := g.client.Do(req)
	if err != nil {
		atomic.AddInt64(&g.errors, 1)
		g.log.Warn("upstream call failed", "err", err)
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 == 2 {
		g.tally(body, ip)
	} else {
		atomic.AddInt64(&g.errors, 1)
	}

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

func (g *gateway) tally(body []byte, ip string) {
	var ur upstreamResp
	if err := json.Unmarshal(body, &ur); err != nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, f := range ur.Data.Result {
		atomic.AddInt64(&g.scanned, 1)
		if f.IsInfected {
			atomic.AddInt64(&g.infected, 1)
			for _, v := range f.Viruses {
				g.viruses[v]++
			}
		}
		now := time.Now()
		a := activity{
			Time:     now.Format("15:04:05"),
			IP:       ip,
			File:     f.Name,
			Infected: f.IsInfected,
			Viruses:  f.Viruses,
		}
		g.recent = append([]activity{a}, g.recent...)
		if len(g.recent) > 20 {
			g.recent = g.recent[:20]
		}
		g.appendLog(logRecord{
			TS:       now.Format(time.RFC3339),
			IP:       ip,
			File:     f.Name,
			Infected: f.IsInfected,
			Viruses:  f.Viruses,
		})
	}
}

type logRecord struct {
	TS       string   `json:"ts"`
	IP       string   `json:"ip"`
	File     string   `json:"file"`
	Infected bool     `json:"infected"`
	Viruses  []string `json:"viruses"`
}

func (g *gateway) appendLog(rec logRecord) {
	if g.logFile == nil {
		return
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	b = append(b, '\n')
	g.logMu.Lock()
	_, _ = g.logFile.Write(b)
	g.logMu.Unlock()
}

func clientIP(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
		return v
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.IndexByte(v, ','); i >= 0 {
			return strings.TrimSpace(v[:i])
		}
		return strings.TrimSpace(v)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// ---- signature DB version polling ----

func (g *gateway) dbLoop() {
	g.refreshDB()
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for range t.C {
		g.refreshDB()
	}
}

func (g *gateway) refreshDB() {
	v, err := clamdVersion(g.clamdAddr, 5*time.Second)
	g.dbMu.Lock()
	defer g.dbMu.Unlock()
	g.dbChecked = time.Now()
	if err != nil {
		g.dbErr = err.Error()
		return
	}
	g.dbErr = ""
	parts := strings.SplitN(v, "/", 3)
	g.dbEngine = strings.TrimSpace(parts[0])
	g.dbVersion, g.dbDate, g.dbBuiltOK = "", "", false
	if len(parts) > 1 {
		g.dbVersion = strings.TrimSpace(parts[1])
	}
	if len(parts) > 2 {
		g.dbDate = strings.TrimSpace(parts[2])
		if t, perr := time.Parse("Mon Jan _2 15:04:05 2006", g.dbDate); perr == nil {
			g.dbBuilt, g.dbBuiltOK = t, true
		}
	}
}

func clamdVersion(addr string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("zVERSION\x00")); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(conn).ReadString(0x00)
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\x00\n "), nil
}

// ---- report export ----

func (g *gateway) handleReport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	from := parseTimeParam(q.Get("from"), time.Time{}, false)
	to := parseTimeParam(q.Get("to"), time.Now(), true)
	format := q.Get("format")
	if format == "" {
		format = "xlsx"
	}

	header := []string{"Время", "IP", "Файл", "Результат", "Вирусы"}
	rows := g.readReport(from, to)
	stamp := time.Now().Format("20060102_1504")

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=report_"+stamp+".csv")
		_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF})
		cw := csv.NewWriter(w)
		_ = cw.Write(header)
		for _, row := range rows {
			_ = cw.Write(row)
		}
		cw.Flush()
	default:
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		w.Header().Set("Content-Disposition", "attachment; filename=report_"+stamp+".xlsx")
		if err := writeXLSX(w, header, rows); err != nil {
			g.log.Error("xlsx", "err", err)
		}
	}
}

func (g *gateway) readReport(from, to time.Time) [][]string {
	var rows [][]string
	f, err := os.Open(g.logPath)
	if err != nil {
		return rows
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for sc.Scan() {
		var rec logRecord
		if json.Unmarshal(sc.Bytes(), &rec) != nil {
			continue
		}
		ts, err := time.Parse(time.RFC3339, rec.TS)
		if err != nil {
			continue
		}
		if !from.IsZero() && ts.Before(from) {
			continue
		}
		if !to.IsZero() && ts.After(to) {
			continue
		}
		res := "чисто"
		if rec.Infected {
			res = "ЗАРАЖЁН"
		}
		rows = append(rows, []string{
			ts.Local().Format("2006-01-02 15:04:05"),
			rec.IP, rec.File, res, strings.Join(rec.Viruses, ", "),
		})
	}
	return rows
}

func parseTimeParam(s string, def time.Time, upper bool) time.Time {
	if s == "" {
		return def
	}
	for _, l := range []string{"2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.ParseInLocation(l, s, time.Local); err == nil {
			if l == "2006-01-02" && upper {
				return t.Add(24 * time.Hour)
			}
			return t
		}
	}
	return def
}

func writeXLSX(w io.Writer, header []string, rows [][]string) error {
	zw := zip.NewWriter(w)
	add := func(name, content string) error {
		f, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = io.WriteString(f, content)
		return err
	}
	if err := add("[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`+
		`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">`+
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>`+
		`<Default Extension="xml" ContentType="application/xml"/>`+
		`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>`+
		`<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`+
		`</Types>`); err != nil {
		return err
	}
	if err := add("_rels/.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`+
		`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`+
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>`+
		`</Relationships>`); err != nil {
		return err
	}
	if err := add("xl/workbook.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`+
		`<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">`+
		`<sheets><sheet name="Otchet" sheetId="1" r:id="rId1"/></sheets></workbook>`); err != nil {
		return err
	}
	if err := add("xl/_rels/workbook.xml.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`+
		`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`+
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>`+
		`</Relationships>`); err != nil {
		return err
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	b.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	writeRow := func(num int, cells []string) {
		b.WriteString(`<row r="`)
		b.WriteString(strconv.Itoa(num))
		b.WriteString(`">`)
		for ci, c := range cells {
			b.WriteString(`<c r="`)
			b.WriteString(colName(ci))
			b.WriteString(strconv.Itoa(num))
			b.WriteString(`" t="inlineStr"><is><t xml:space="preserve">`)
			b.WriteString(xmlEscape(c))
			b.WriteString(`</t></is></c>`)
		}
		b.WriteString(`</row>`)
	}
	writeRow(1, header)
	for i, row := range rows {
		writeRow(i+2, row)
	}
	b.WriteString(`</sheetData></worksheet>`)
	if err := add("xl/worksheets/sheet1.xml", b.String()); err != nil {
		return err
	}
	return zw.Close()
}

func colName(i int) string {
	name := ""
	for i >= 0 {
		name = string(rune('A'+i%26)) + name
		i = i/26 - 1
	}
	return name
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// ---- stats / dashboard ----

type virusStat struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

func (g *gateway) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"status":"ok"}`)
}

func (g *gateway) handleStats(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	top := make([]virusStat, 0, len(g.viruses))
	for n, c := range g.viruses {
		top = append(top, virusStat{Name: n, Count: c})
	}
	recent := make([]activity, len(g.recent))
	copy(recent, g.recent)
	g.mu.Unlock()

	sort.Slice(top, func(i, j int) bool { return top[i].Count > top[j].Count })
	if len(top) > 10 {
		top = top[:10]
	}

	db := map[string]any{}
	g.dbMu.RLock()
	db["engine"] = g.dbEngine
	db["version"] = g.dbVersion
	db["date"] = g.dbDate
	db["error"] = g.dbErr
	if !g.dbChecked.IsZero() {
		db["checked_seconds_ago"] = int64(time.Since(g.dbChecked).Seconds())
	}
	if g.dbBuiltOK {
		db["age_hours"] = int64(time.Since(g.dbBuilt).Hours())
	}
	g.dbMu.RUnlock()

	out := map[string]any{
		"scanned":        atomic.LoadInt64(&g.scanned),
		"infected":       atomic.LoadInt64(&g.infected),
		"errors":         atomic.LoadInt64(&g.errors),
		"active":         atomic.LoadInt64(&g.active),
		"waiting":        atomic.LoadInt64(&g.waiting),
		"max_concurrent": g.maxConc,
		"uptime_seconds": int64(time.Since(g.startedAt).Seconds()),
		"top_viruses":    top,
		"recent":         recent,
		"database":       db,
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(out)
}

func (g *gateway) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, dashboardHTML)
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
func getint(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}
func getdur(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

var dashboardHTML = `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ClamAV — мониторинг</title>
<style>
  :root { --bg:#0d1117; --card:#161b22; --line:#30363d; --fg:#e6edf3; --mut:#8b949e;
          --ok:#3fb950; --bad:#f85149; --warn:#d29922; --acc:#58a6ff; }
  * { box-sizing:border-box; }
  body { margin:0; font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;
         background:var(--bg); color:var(--fg); padding:24px; }
  h1 { font-size:18px; margin:0 0 4px; }
  .sub { color:var(--mut); margin-bottom:20px; font-size:12px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
          gap:12px; margin-bottom:20px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:8px;
          padding:14px 16px; }
  .card .k { color:var(--mut); font-size:11px; text-transform:uppercase;
             letter-spacing:.05em; }
  .card .v { font-size:28px; font-weight:600; margin-top:4px; }
  .v.ok{color:var(--ok)} .v.bad{color:var(--bad)} .v.warn{color:var(--warn)} .v.acc{color:var(--acc)}
  .row { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
  @media(max-width:700px){ .row{grid-template-columns:1fr} }
  .panel { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:16px; }
  .panel h2 { font-size:13px; margin:0 0 12px; color:var(--mut); text-transform:uppercase;
              letter-spacing:.05em; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  td,th { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); }
  th { color:var(--mut); font-weight:500; }
  .virus { color:var(--bad); }
  .empty { color:var(--mut); font-style:italic; }
  .bar { height:6px; background:var(--line); border-radius:3px; overflow:hidden; margin-top:8px; }
  .bar > i { display:block; height:100%; background:var(--acc); width:0; transition:width .3s; }
  .dot { display:inline-block; width:8px; height:8px; border-radius:50%; background:var(--ok);
         margin-right:6px; vertical-align:middle; }
  .dbmeta { color:var(--mut); font-size:12px; margin-top:6px; }
  .exp { display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-top:10px; }
  .exp label { color:var(--mut); font-size:12px; }
  .exp input[type=date] { background:var(--bg); color:var(--fg); border:1px solid var(--line);
    border-radius:6px; padding:6px 8px; font:inherit; }
  .exp button { background:var(--acc); color:#0d1117; border:0; border-radius:6px;
    padding:7px 14px; font:inherit; font-weight:600; cursor:pointer; }
  .exp button.alt { background:transparent; color:var(--acc); border:1px solid var(--acc); }
</style>
</head>
<body>
  <h1><span class="dot"></span>ClamAV — мониторинг</h1>
  <div class="sub" id="meta">обновление каждые 2 с…</div>

  <div class="grid">
    <div class="card"><div class="k">Проверено файлов</div><div class="v acc" id="scanned">—</div></div>
    <div class="card"><div class="k">Обнаружено вирусов</div><div class="v bad" id="infected">—</div></div>
    <div class="card"><div class="k">Сканируется сейчас</div><div class="v warn" id="active">—</div></div>
    <div class="card"><div class="k">В очереди</div><div class="v" id="waiting">—</div></div>
    <div class="card"><div class="k">Ошибки</div><div class="v" id="errors">—</div></div>
  </div>

  <div class="row" style="margin-bottom:20px">
    <div class="card">
      <div class="k">Загрузка движка (активные / лимит)</div>
      <div class="v acc" id="load">—</div>
      <div class="bar"><i id="loadbar"></i></div>
    </div>
    <div class="card">
      <div class="k">База сигнатур</div>
      <div class="v" id="dbver" style="font-size:18px">—</div>
      <div class="dbmeta" id="dbmeta"></div>
    </div>
  </div>

  <div class="card" style="margin-bottom:20px">
    <div class="k">Выгрузка отчёта за период</div>
    <div class="exp">
      <label>с <input type="date" id="from"></label>
      <label>по <input type="date" id="to"></label>
      <button onclick="dl('xlsx')">Excel (.xlsx)</button>
      <button class="alt" onclick="dl('csv')">CSV</button>
    </div>
  </div>

  <div class="row">
    <div class="panel">
      <h2>Последние загрузки</h2>
      <table><thead><tr><th>Время</th><th>IP</th><th>Файл</th><th>Результат</th></tr></thead>
        <tbody id="recent"><tr><td colspan="4" class="empty">пока пусто</td></tr></tbody></table>
    </div>
    <div class="panel">
      <h2>Топ сигнатур</h2>
      <table><thead><tr><th>Вирус</th><th>Срабатываний</th></tr></thead>
        <tbody id="top"><tr><td colspan="2" class="empty">пока пусто</td></tr></tbody></table>
    </div>
  </div>

<script>
function fmtUptime(s){ var h=Math.floor(s/3600),m=Math.floor(s%3600/60); return h+"ч "+m+"м"; }
function fmtAgo(s){ if(s==null) return "—"; if(s<60) return s+" с"; if(s<3600) return Math.floor(s/60)+" мин"; return Math.floor(s/3600)+" ч"; }
async function tick(){
  try {
    const r = await fetch('/stats',{cache:'no-store'});
    const d = await r.json();
    document.getElementById('scanned').textContent  = d.scanned;
    document.getElementById('infected').textContent = d.infected;
    document.getElementById('active').textContent   = d.active;
    document.getElementById('waiting').textContent  = d.waiting;
    document.getElementById('errors').textContent   = d.errors;
    document.getElementById('load').textContent     = d.active + " / " + d.max_concurrent;
    document.getElementById('loadbar').style.width  = Math.min(100, d.active/d.max_concurrent*100) + "%";
    document.getElementById('meta').textContent     = "аптайм " + fmtUptime(d.uptime_seconds) + " · обновлено " + new Date().toLocaleTimeString();

    const db = d.database||{};
    const dbver = document.getElementById('dbver');
    if (db.error) {
      dbver.textContent = "нет связи с движком";
      dbver.className = "v bad";
      document.getElementById('dbmeta').textContent = esc(db.error);
    } else if (db.version) {
      dbver.textContent = "daily v" + db.version;
      var age = db.age_hours;
      dbver.className = "v " + (age==null ? "" : (age<48 ? "ok" : (age<96 ? "warn" : "bad")));
      var parts = [];
      if (db.date) parts.push("собрана " + esc(db.date));
      if (age!=null) parts.push("возраст " + age + " ч");
      parts.push("проверено " + fmtAgo(db.checked_seconds_ago) + " назад");
      if (db.engine) parts.push(esc(db.engine));
      document.getElementById('dbmeta').textContent = parts.join(" · ");
    } else {
      dbver.textContent = "…";
    }

    const rec = d.recent||[];
    document.getElementById('recent').innerHTML = rec.length
      ? rec.map(function(x){
          var res = x.infected
            ? "<span class='virus'>ЗАРАЖЁН: "+esc((x.viruses||[]).join(', '))+"</span>"
            : "<span style='color:var(--ok)'>чисто</span>";
          return "<tr><td>"+x.time+"</td><td>"+esc(x.ip||'—')+"</td><td>"+esc(x.file)+"</td><td>"+res+"</td></tr>";
        }).join('')
      : "<tr><td colspan='4' class='empty'>пока пусто</td></tr>";

    const top = d.top_viruses||[];
    document.getElementById('top').innerHTML = top.length
      ? top.map(x=>"<tr><td class='virus'>"+esc(x.name)+"</td><td>"+x.count+"</td></tr>").join('')
      : "<tr><td colspan='2' class='empty'>пока пусто</td></tr>";
  } catch(e){ document.getElementById('meta').textContent = "нет связи с сервисом…"; }
}
function esc(s){ return String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
function dl(fmt){
  var f=document.getElementById('from').value, t=document.getElementById('to').value;
  var u='/report?format='+fmt;
  if(f) u+='&from='+encodeURIComponent(f);
  if(t) u+='&to='+encodeURIComponent(t);
  window.location=u;
}
tick(); setInterval(tick, 2000);
</script>
</body>
</html>`
