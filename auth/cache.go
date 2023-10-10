package auth

import (
	"sync"
	"time"
)

var once sync.Once
var cache Store

// InitCache intializes the pacakge cache with the provided cache object.
// Consumers that want automatic caching when using `GetRegistryAuthenticator()`
// or `GetGitCredentials()` must call this before. It should only be called once,
// all subsequent calls will be a no-op.
func InitCache(s Store) {
	once.Do(func() {
		cache = s
	})
}

// Store is a general purpose key value store.
type Store interface {
	Set(key string, val interface{}, ttl time.Duration) error
	Get(key string) (interface{}, bool)
}
