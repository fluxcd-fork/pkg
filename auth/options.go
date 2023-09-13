package auth

import (
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
)

var once sync.Once
var cache Store

// InitCache intializes the pacakge cache with the provided cache object.
// Consumers that want automatic caching when using `registry.GetAuthenticator()`
// or `git.GetCredentials()` must call this before. It can also be called once,
// all future calls will be a no-op.
func InitCache(s Store) {
	once.Do(func() {
		cache = s
	})
}

func GetCache() Store {
	return cache
}

const (
	AWS_PROVIDER   = "aws"
	AZURE_PROVIDER = "azure"
	GCP_PROVIDER   = "gcp"
)

// AuthOptions contains options that can be used for authentication.
type AuthOptions struct {
	// Secret contains information that can be used to obtain the required
	// set of credentials.
	Secret *corev1.Secret
	// ServiceAccount is the identity to impersonate while obtaining the
	// required set of credentials.
	ServiceAccount *corev1.ServiceAccount
	// CacheKey is the key to use for caching the authentication credentials.
	// Consumers must make sure to call `InitCache()` in order for caching to
	// be enabled.
	CacheKey string
}

// Store is a general purpose key value store.
type Store interface {
	Set(key string, val interface{}, ttl time.Duration) error
	Get(key string) (interface{}, bool)
}
