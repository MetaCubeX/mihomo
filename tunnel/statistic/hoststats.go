package statistic

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// trafficStatsMinuteBucket 是分钟桶的保留时长，超出后只由日桶承载。
	trafficStatsMinuteBucket = 24 * time.Hour
	trafficStatsFileVersion  = 1
	defaultMaxHosts          = 20000
	defaultRetentionDays     = 30
)

// TrafficStatsOptions 是统计模块的初始化参数，由配置解析处传入。
type TrafficStatsOptions struct {
	Enabled         bool
	RetentionDays   int
	MaxHosts        int
	PersistInterval time.Duration
	Path            string
}

type trafficCounter struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

type trafficBucket struct {
	Proxy  trafficCounter `json:"proxy"`
	Direct trafficCounter `json:"direct"`
}

type hostStat struct {
	Minute map[int64]*trafficBucket `json:"minute"`
	Day    map[int64]*trafficBucket `json:"day"`
	Conns  int64                    `json:"conns"`
	Last   int64                    `json:"last"`
}

type trafficStatsFile struct {
	Version int                   `json:"version"`
	Hosts   map[string]*hostStat  `json:"hosts"`
	Since   int64                 `json:"since"`
}

// TrafficStats 按域名累计流量，区分代理与直连，分钟桶 + 日桶两级。
type TrafficStats struct {
	mu              sync.Mutex
	enabled         bool
	hosts           map[string]*hostStat
	lastSample      map[string]trafficCounter
	retentionDays   int
	maxHosts        int
	persistInterval time.Duration
	path            string
	since           int64
	totalUp         int64
	totalDown       int64
	// 会话内增量，与内核全局计数的基线差值对账
	sessionUp       int64
	sessionDown     int64
	kernelBaseUp    int64
	kernelBaseDown  int64
	stopCh          chan struct{}
	stopOnce        sync.Once
}

// HostTrafficResult 是单条域名统计结果。
type HostTrafficResult struct {
	Host   string         `json:"host"`
	Proxy  trafficCounter `json:"proxy"`
	Direct trafficCounter `json:"direct"`
	Conns  int64          `json:"conns"`
	Last   int64          `json:"last_seen"`
}

// TrafficHostsResponse 是 /traffic/hosts 的响应体。
type TrafficHostsResponse struct {
	Since  int64               `json:"since"`
	Until  int64               `json:"until"`
	Totals map[string]trafficCounter `json:"totals"`
	Hosts  []HostTrafficResult `json:"hosts"`
}

// TrafficCheckResponse 是 /traffic/hosts/check 的响应体，用于与内核全局计数对账。
type TrafficCheckResponse struct {
	Stats  trafficCounter `json:"stats"`
	Kernel trafficCounter `json:"kernel"`
	Diff   trafficCounter `json:"diff"`
}

// InitTrafficStats 由配置解析完成后调用，初始化全局统计实例。
func InitTrafficStats(opts TrafficStatsOptions) {
	if defaultTrafficStats != nil {
		defaultTrafficStats.Close() // 重载配置前先落盘并停止旧实例
	}
	stats := NewTrafficStats(opts)
	defaultTrafficStats = stats
	if stats.enabled && opts.PersistInterval > 0 {
		stats.startPersistLoop()
	}
}

var defaultTrafficStats *TrafficStats

// GetTrafficStats 返回全局统计实例，未初始化时为 nil。
func GetTrafficStats() *TrafficStats {
	return defaultTrafficStats
}

// NewTrafficStats 构造统计实例，参数非法时回落到默认值。
func NewTrafficStats(opts TrafficStatsOptions) *TrafficStats {
	if opts.RetentionDays <= 0 {
		opts.RetentionDays = defaultRetentionDays
	}
	if opts.MaxHosts <= 0 {
		opts.MaxHosts = defaultMaxHosts
	}
	kernelUp, kernelDown := DefaultManager.Total()
	s := &TrafficStats{
		kernelBaseUp:    kernelUp,
		kernelBaseDown:  kernelDown,
		enabled:         opts.Enabled,
		hosts:           make(map[string]*hostStat),
		lastSample:      make(map[string]trafficCounter),
		retentionDays:   opts.RetentionDays,
		maxHosts:        opts.MaxHosts,
		persistInterval: opts.PersistInterval,
		path:            opts.Path,
		since:           time.Now().Unix(),
		stopCh:          make(chan struct{}),
	}
	if s.enabled && opts.Path != "" {
		s.load()
	}
	return s
}

// Enabled 表示统计是否开启。
func (s *TrafficStats) Enabled() bool {
	return s != nil && s.enabled
}

// Sample 用当前活跃连接快照推进增量。每秒调用一次。
func (s *TrafficStats) Sample(infos []*TrackerInfo, now time.Time) {
	if !s.Enabled() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	seen := make(map[string]struct{}, len(infos))
	for _, info := range infos {
		if info == nil || info.Metadata == nil {
			continue
		}
		id := info.UUID.String()
		seen[id] = struct{}{}
		cur := trafficCounter{Up: info.UploadTotal.Load(), Down: info.DownloadTotal.Load()}
		prev, ok := s.lastSample[id]
		if !ok {
			s.lastSample[id] = cur
			s.addLocked(info, cur.Up, cur.Down, now)
			continue
		}
		du, dd := cur.Up-prev.Up, cur.Down-prev.Down
		if du < 0 || dd < 0 { // 计数器回退，按全量处理
			du, dd = cur.Up, cur.Down
		}
		if du == 0 && dd == 0 {
			continue
		}
		s.addLocked(info, du, dd, now)
		s.lastSample[id] = cur
	}
	// 防御：已不在快照里的连接说明已关闭，避免状态泄漏。
	for id := range s.lastSample {
		if _, ok := seen[id]; !ok {
			delete(s.lastSample, id)
		}
	}
}

// OnClose 在连接关闭时结算最后一段增量。
func (s *TrafficStats) OnClose(info *TrackerInfo) {
	if !s.Enabled() || info == nil || info.Metadata == nil {
		return
	}
	id := info.UUID.String()
	cur := trafficCounter{Up: info.UploadTotal.Load(), Down: info.DownloadTotal.Load()}

	s.mu.Lock()
	defer s.mu.Unlock()

	prev, ok := s.lastSample[id]
	delete(s.lastSample, id)
	du, dd := cur.Up, cur.Down
	if ok {
		du, dd = cur.Up-prev.Up, cur.Down-prev.Down
	}
	if du < 0 || dd < 0 {
		du, dd = cur.Up, cur.Down
	}
	if du != 0 || dd != 0 {
		s.addLocked(info, du, dd, time.Now())
	}
	host := hostOf(info)
	if hs := s.hosts[host]; hs != nil {
		hs.Conns++
	}
}

func (s *TrafficStats) addLocked(info *TrackerInfo, up, down int64, at time.Time) {
	if up == 0 && down == 0 {
		return
	}
	host := hostOf(info)
	direct := isDirectChain(info.Chain)

	hs := s.hosts[host]
	if hs == nil {
		if len(s.hosts) >= s.maxHosts {
			s.evictLocked()
			if len(s.hosts) >= s.maxHosts {
				return // 达到上限，丢弃新域名
			}
		}
		hs = &hostStat{
			Minute: make(map[int64]*trafficBucket),
			Day:    make(map[int64]*trafficBucket),
		}
		s.hosts[host] = hs
	}

	minute := at.Unix() / 60
	day := at.Unix() / 86400
	for _, m := range []map[int64]*trafficBucket{hs.Minute} {
		b := m[minute]
		if b == nil {
			b = &trafficBucket{}
			m[minute] = b
		}
		applyBucket(b, direct, up, down)
	}
	b := hs.Day[day]
	if b == nil {
		b = &trafficBucket{}
		hs.Day[day] = b
	}
	applyBucket(b, direct, up, down)

	hs.Last = at.Unix()
	s.totalUp += up
	s.totalDown += down
	s.sessionUp += up
	s.sessionDown += down
}

func applyBucket(b *trafficBucket, direct bool, up, down int64) {
	if direct {
		b.Direct.Up += up
		b.Direct.Down += down
		return
	}
	b.Proxy.Up += up
	b.Proxy.Down += down
}

// evictLocked 淘汰最久未更新的域名，释放约 10% 空间。
func (s *TrafficStats) evictLocked() {
	type entry struct {
		host string
		last int64
	}
	list := make([]entry, 0, len(s.hosts))
	for h, st := range s.hosts {
		list = append(list, entry{host: h, last: st.Last})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].last < list[j].last })
	for i := 0; i < len(list)/10+1 && i < len(list); i++ {
		delete(s.hosts, list[i].host)
	}
}

// Query 按时间区间与域名条件聚合。
func (s *TrafficStats) Query(since, until int64, domain string, suffixMatch bool, group string, top int) TrafficHostsResponse {
	resp := TrafficHostsResponse{
		Since:  since,
		Until:  until,
		Totals: map[string]trafficCounter{"proxy": {}, "direct": {}},
		Hosts:  []HostTrafficResult{},
	}
	if !s.Enabled() {
		return resp
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().Unix()
	minuteWindow := (now - int64(trafficStatsMinuteBucket/time.Second)) / 60
	dayLimit := now - int64(s.retentionDays)*86400

	for host, hs := range s.hosts {
		if domain != "" {
			if suffixMatch {
				if !strings.HasSuffix(host, domain) {
					continue
				}
			} else if host != domain {
				continue
			}
		}

		var res HostTrafficResult
		res.Host = host

		for m, b := range hs.Minute {
			ts := m * 60
			if ts < since || ts > until || m < minuteWindow {
				continue
			}
			sumBucket(&res, b, group)
		}
		for d, b := range hs.Day {
			dayStart := d * 86400
			if dayStart >= minuteWindow*60 || dayStart < since || dayStart < dayLimit || dayStart+86400 > until+86400 {
				continue
			}
			sumBucket(&res, b, group)
		}
		if res.Proxy.Up == 0 && res.Proxy.Down == 0 && res.Direct.Up == 0 && res.Direct.Down == 0 {
			continue
		}
		res.Conns = hs.Conns
		res.Last = hs.Last
		resp.Hosts = append(resp.Hosts, res)

		resp.Totals["proxy"] = addCounter(resp.Totals["proxy"], res.Proxy)
		resp.Totals["direct"] = addCounter(resp.Totals["direct"], res.Direct)
	}

	sort.Slice(resp.Hosts, func(i, j int) bool {
		a := resp.Hosts[i].Proxy.Up + resp.Hosts[i].Proxy.Down + resp.Hosts[i].Direct.Up + resp.Hosts[i].Direct.Down
		b := resp.Hosts[j].Proxy.Up + resp.Hosts[j].Proxy.Down + resp.Hosts[j].Direct.Up + resp.Hosts[j].Direct.Down
		return a > b
	})
	if top > 0 && len(resp.Hosts) > top {
		resp.Hosts = resp.Hosts[:top]
	}
	return resp
}

func sumBucket(res *HostTrafficResult, b *trafficBucket, group string) {
	switch group {
	case "proxy":
		res.Proxy = addCounter(res.Proxy, b.Proxy)
	case "direct":
		res.Direct = addCounter(res.Direct, b.Direct)
	default:
		res.Proxy = addCounter(res.Proxy, b.Proxy)
		res.Direct = addCounter(res.Direct, b.Direct)
	}
}

func addCounter(a, b trafficCounter) trafficCounter {
	return trafficCounter{Up: a.Up + b.Up, Down: a.Down + b.Down}
}

// Check 返回统计累计与内核全局计数的差值。
func (s *TrafficStats) Check() TrafficCheckResponse {
	var stats trafficCounter
	var baseUp, baseDown int64
	if s.Enabled() {
		s.mu.Lock()
		stats = trafficCounter{Up: s.sessionUp, Down: s.sessionDown}
		baseUp, baseDown = s.kernelBaseUp, s.kernelBaseDown
		s.mu.Unlock()
	}
	kernelUp, kernelDown := DefaultManager.Total()
	// 只比较本进程启动以来的增量，避免把统计初始化之前的流量算成漏计
	kernel := trafficCounter{Up: kernelUp - baseUp, Down: kernelDown - baseDown}
	return TrafficCheckResponse{
		Stats:  stats,
		Kernel: kernel,
		Diff:   trafficCounter{Up: stats.Up - kernel.Up, Down: stats.Down - kernel.Down},
	}
}

func hostOf(info *TrackerInfo) string {
	host := ""
	if info.Metadata != nil {
		host = info.Metadata.Host
		if host == "" && info.Metadata.DstIP.IsValid() {
			host = info.Metadata.DstIP.String()
		}
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return "unknown"
	}
	return host
}

func isDirectChain(chain []string) bool {
	for _, name := range chain {
		if strings.EqualFold(name, "DIRECT") {
			return true
		}
	}
	return len(chain) == 0
}

func (s *TrafficStats) startPersistLoop() {
	go func() {
		ticker := time.NewTicker(s.persistInterval)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.prune()
				_ = s.Save()
			}
		}
	}()
}

// Close 停止后台任务并落盘。
func (s *TrafficStats) Close() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() { close(s.stopCh) })
	_ = s.Save()
}

func (s *TrafficStats) prune() {
	s.mu.Lock()
	defer s.mu.Unlock()

	minuteLimit := time.Now().Add(-trafficStatsMinuteBucket).Unix() / 60
	dayLimit := time.Now().Unix() - int64(s.retentionDays)*86400
	dayLimit /= 86400

	for host, hs := range s.hosts {
		for m := range hs.Minute {
			if m < minuteLimit {
				delete(hs.Minute, m)
			}
		}
		for d := range hs.Day {
			if d < dayLimit {
				delete(hs.Day, d)
			}
		}
		if len(hs.Minute) == 0 && len(hs.Day) == 0 {
			delete(s.hosts, host)
		}
	}
}

// Save 把统计写入磁盘。
func (s *TrafficStats) Save() error {
	if !s.Enabled() || s.path == "" {
		return nil
	}
	s.mu.Lock()
	data := trafficStatsFile{
		Version: trafficStatsFileVersion,
		Hosts:   s.hosts,
		Since:   s.since,
	}
	raw, err := json.Marshal(data)
	s.mu.Unlock()
	if err != nil {
		return err
	}

	dir := filepath.Dir(s.path)
	if dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *TrafficStats) load() {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var data trafficStatsFile
	if err := json.Unmarshal(raw, &data); err != nil || data.Version != trafficStatsFileVersion {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if data.Hosts != nil {
		s.hosts = data.Hosts
	}
	if data.Since > 0 {
		s.since = data.Since
	}
	for _, hs := range s.hosts {
		if hs.Minute == nil {
			hs.Minute = make(map[int64]*trafficBucket)
		}
		if hs.Day == nil {
			hs.Day = make(map[int64]*trafficBucket)
		}
	}
}
