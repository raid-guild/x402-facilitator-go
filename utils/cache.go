package utils

import (
	"sync"
)

// SingleCache provides thread-safe caching for a single value, reused with warm instances.
// The value is initialized once on success and cached for subsequent calls.
type SingleCache[T any] struct {
	mu          sync.RWMutex
	value       T
	initialized bool
}

// Get returns the cached value, initializing it on the first call using the provided init function.
// Subsequent calls return the successfully cached value, without re-initialization.
func (c *SingleCache[T]) Get(init func() (T, error)) (T, error) {

	// Get the cached value if it exists
	c.mu.RLock()
	initialized := c.initialized
	value := c.value
	c.mu.RUnlock()

	// Return the cached value if it exists
	if initialized {
		return value, nil
	}

	// Initialize and only cache on success
	c.mu.Lock()
	if c.initialized {
		value = c.value
		c.mu.Unlock()
		return value, nil
	}
	newValue, err := init()
	if err != nil {
		c.mu.Unlock()
		return newValue, err
	}
	c.value = newValue
	c.initialized = true
	c.mu.Unlock()

	// Return the cached value
	return newValue, nil
}

// Reset clears the cache, allowing it to be re-initialized on the next Get call.
// This is primarily useful for testing when environment variables or other inputs change.
func (c *SingleCache[T]) Reset() {
	c.mu.Lock()
	var zero T
	c.value = zero
	c.initialized = false
	c.mu.Unlock()
}

// KeyedCache provides thread-safe caching for multiple values, reused with warm instances.
// Each key is initialized once on success and cached for subsequent calls with the same key.
type KeyedCache[T any] struct {
	mu     sync.RWMutex
	caches map[string]*SingleCache[T]
}

// NewKeyedCache creates a new KeyedCache.
func NewKeyedCache[T any]() *KeyedCache[T] {
	return &KeyedCache[T]{
		caches: make(map[string]*SingleCache[T]),
	}
}

// Get returns the cached value for the given key, initializing it on the first call with that key.
// Subsequent calls with the same key return the cached value without re-initialization.
func (kc *KeyedCache[T]) Get(key string, init func() (T, error)) (T, error) {

	// Get the cache if it exists
	kc.mu.RLock()
	cache, exists := kc.caches[key]
	kc.mu.RUnlock()

	// Return the cached value if the cache exists
	if exists {
		return cache.Get(init)
	}

	// Create the cache if it does not exist
	kc.mu.Lock()
	cache, exists = kc.caches[key]
	if !exists {
		cache = &SingleCache[T]{}
		kc.caches[key] = cache
	}
	kc.mu.Unlock()

	// Return the cached value
	return cache.Get(init)
}

// Reset clears the cache for the given key, allowing it to be re-initialized on the next Get call.
// This is primarily useful for testing when environment variables or other inputs change.
func (kc *KeyedCache[T]) Reset(key string) {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	if cache, exists := kc.caches[key]; exists {
		cache.Reset()
	}
}

// ResetAll clears all cached values, allowing them to be re-initialized on the next Get call.
// This is primarily useful for testing when environment variables or other inputs change.
func (kc *KeyedCache[T]) ResetAll() {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	for _, cache := range kc.caches {
		cache.Reset()
	}
}
