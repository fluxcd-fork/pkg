package registry

import (
	"context"
	"fmt"
	"time"

	"github.com/fluxcd/pkg/auth"
	"github.com/fluxcd/pkg/auth/aws"
	"github.com/fluxcd/pkg/auth/azure"
	"github.com/fluxcd/pkg/auth/gcp"
	"github.com/google/go-containerregistry/pkg/authn"
)

// GetAuthenticator returns an Authenticator that can provide authentication
// credentials required to login to the OCI registry that hosts the image.
// If `authOptions.CacheKey` isn't empty and caching has been enabled via
// `auth.InitCache()`, then the cache key is used to cache the authentication
// config. The authentication config is evicted from the cache after it's
// expiration time, as advertised by the provider.
func GetAuthenticator(ctx context.Context, image string, provider string,
	authOptions *auth.AuthOptions) (authn.Authenticator, error) {
	var authConfig authn.AuthConfig
	cache := auth.GetCache()
	if cache != nil && authOptions.CacheKey != "" {
		val, found := cache.Get(authOptions.CacheKey)
		if found {
			authConfig = val.(authn.AuthConfig)
			return authn.FromConfig(authConfig), nil
		}
	}

	var err error
	var expiresIn time.Duration
	switch provider {
	case auth.AWS_PROVIDER:
		authConfig, expiresIn, err = aws.GetECRAuthConfig(ctx, image, authOptions)
	case auth.AZURE_PROVIDER:
		authConfig, expiresIn, err = azure.GetACRAuthConfig(ctx, image, authOptions)
	case auth.GCP_PROVIDER:
		authConfig, expiresIn, err = gcp.GetGCRAuthConfig(ctx, authOptions)
	default:
		return nil, fmt.Errorf("unsupported registry provider: %s", provider)
	}
	if err != nil {
		return nil, err
	}

	if cache != nil && authOptions.CacheKey != "" {
		if err := cache.Set(authOptions.CacheKey, authConfig, expiresIn); err != nil {
			return nil, err
		}
	}

	return authn.FromConfig(authConfig), nil
}
