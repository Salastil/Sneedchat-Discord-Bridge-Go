package utils

import (
	"sync"
	"time"
)

type BoundedMap struct {
	mu         sync.RWMutex
	data       map[string]interface{}
	timestamps map[string]time.Time
	maxSize    int
	maxAge     time.Duration
	keys       []string
}

func NewBoundedMap(maxSize int, maxAge time.Duration) *BoundedMap {
	return &BoundedMap{
		data:       make(map[string]interface{}),
		timestamps: make(map[string]time.Time),
		maxSize:    maxSize,
		maxAge:     maxAge,
		keys:       make([]string, 0, maxSize),
	}
}

func (bm *BoundedMap) Set(key string, value interface{}) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	if _, ok := bm.data[key]; ok {
		bm.data[key] = value
		bm.timestamps[key] = time.Now()
		for i, k := range bm.keys {
			if k == key {
				bm.keys = append(bm.keys[:i], bm.keys[i+1:]...)
				break
			}
		}
		bm.keys = append(bm.keys, key)
		return
	}
	bm.data[key] = value
	bm.timestamps[key] = time.Now()
	bm.keys = append(bm.keys, key)
	if len(bm.data) > bm.maxSize {
		oldest := bm.keys[0]
		delete(bm.data, oldest)
		delete(bm.timestamps, oldest)
		bm.keys = bm.keys[1:]
	}
}

func (bm *BoundedMap) Get(key string) (interface{}, bool) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	v, ok := bm.data[key]
	return v, ok
}

func (bm *BoundedMap) Delete(key string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	delete(bm.data, key)
	delete(bm.timestamps, key)
	for i, k := range bm.keys {
		if k == key {
			bm.keys = append(bm.keys[:i], bm.keys[i+1:]...)
			break
		}
	}
}

func (bm *BoundedMap) CleanupOldEntries() int {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	now := time.Now()
	removed := 0
	for key, ts := range bm.timestamps {
		if now.Sub(ts) > bm.maxAge {
			delete(bm.data, key)
			delete(bm.timestamps, key)
			for i, k := range bm.keys {
				if k == key {
					bm.keys = append(bm.keys[:i], bm.keys[i+1:]...)
					break
				}
			}
			removed++
		}
	}
	return removed
}

func (bm *BoundedMap) Len() int {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return len(bm.data)
}
