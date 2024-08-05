package cni0

import "sync"

type Mapping struct {
	cb   func()
	dict map[string]string
	sync.RWMutex
}

func NewMapping() *Mapping {
	size := 1000
	return &Mapping{
		dict: make(map[string]string, size),
	}
}

func (m *Mapping) Add(k, v string) {
	m.Lock()
	defer m.Unlock()

	m.dict[k] = v
}

func (m *Mapping) Get(k string) string {
	m.RLock()
	defer m.RUnlock()

	return m.dict[k]
}
