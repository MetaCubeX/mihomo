package statistic

func (m *Manager) Total() (up, down int64) {
	return m.uploadTotal.Load(), m.downloadTotal.Load()
}
