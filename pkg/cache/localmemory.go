package cache

import (
	"container/list"
	"context"
	"sync"
	"time"
)

// LocalMemCache is an in-process, local memory cache implementation of a cache
// service. The usual approach is to use dedicated services like Memcached or
// Redis, but for a single process, stateful application, using local memory is
// a valid option as well.
// LocalMemCache does not provide snapshots support or any other form of state
// persistence.
type LocalMemCache struct {
	maxMemory uint64

	mu         sync.Mutex
	usedMemory uint64
	lru        *list.List
	mem        map[string]*cacheitem

	// Keep track of mem max size.
	memCap uint
}

type cacheitem struct {
	Key     string
	Value   []byte
	ExpAt   time.Time
	lruItem *list.Element
}

var _ Store = (*LocalMemCache)(nil)

// NewLocalMemCache returns local memory cache intance.
//
// If maxMemory if provided, it defines how many bytes can be used before the
// LRU starts evicting entries. If set to 0, there is no memory limit and
// entries are never evicted.
// Counted memory size is only for the stored serialized value, not for the
// whole memory an item in cache takes.
func NewLocalMemCache(maxMemory uint64) *LocalMemCache {
	return &LocalMemCache{
		maxMemory: maxMemory,
		lru:       list.New(),
		mem:       make(map[string]*cacheitem, 1024),
		memCap:    0,
	}
}

func (c *LocalMemCache) deleteItem(it *cacheitem) {
	delete(c.mem, it.Key)
	c.lru.Remove(it.lruItem)
	c.usedMemory -= uint64(len(it.Value))

	if size := uint(len(c.mem)); size < c.memCap/10 {
		// Go map is never resized down. The size of the map shrinked
		// 10x, in order to free some memory, realocate the map.
		mem := make(map[string]*cacheitem, len(c.mem)*2)
		for k, v := range c.mem {
			mem[k] = v
		}
		c.mem = mem
	}
}

func (c *LocalMemCache) storeItem(key string, value []byte, exp time.Duration) {
	it := &cacheitem{
		Key:   key,
		Value: value,
		ExpAt: time.Now().Add(exp),
	}
	it.lruItem = c.lru.PushFront(it)
	c.mem[key] = it
	c.usedMemory += uint64(len(it.Value))

	if size := uint(len(c.mem)); size > c.memCap {
		c.memCap = size
	}

	for c.maxMemory > 0 && c.usedMemory > c.maxMemory {
		it := c.lru.Back().Value.(*cacheitem)
		c.deleteItem(it)
	}
}

func (c *LocalMemCache) Get(ctx context.Context, key string, dest interface{}) error {
	c.mu.Lock()

	it, ok := c.mem[key]
	if !ok {
		c.mu.Unlock()
		return ErrMiss
	}

	if it.ExpAt.Before(time.Now()) {
		c.deleteItem(it)
		c.mu.Unlock()
		return ErrMiss
	}

	c.lru.MoveToFront(it.lruItem)

	c.mu.Unlock()

	if err := unmarshal(it.Value, dest); err != nil {
		return err
	}
	return nil
}

func (c *LocalMemCache) Set(ctx context.Context, key string, value interface{}, exp time.Duration) error {
	b, err := marshal(value)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.storeItem(key, b, exp)
	c.mu.Unlock()

	return nil
}

func (c *LocalMemCache) SetNx(ctx context.Context, key string, value interface{}, exp time.Duration) error {
	// Serialize before checking for conflict to hold the lock for as
	// little as possible.
	b, err := marshal(value)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if it, ok := c.mem[key]; ok {
		if it.ExpAt.After(time.Now()) {
			return ErrConflict
		}
		c.deleteItem(it)
	}

	c.storeItem(key, b, exp)
	return nil
}

func (c *LocalMemCache) Del(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	it, ok := c.mem[key]
	if !ok {
		return ErrMiss
	}
	c.deleteItem(it)
	return nil
}

func (c *LocalMemCache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()

	*c = *NewLocalMemCache(c.maxMemory)
}
