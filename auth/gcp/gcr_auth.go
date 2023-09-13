package gcp

import (
	"context"
	"time"

	"github.com/fluxcd/pkg/auth"
	"github.com/google/go-containerregistry/pkg/authn"
)

// GetGCRAuthConfig returns an AuthConfig that contains the credentials
// required to authenticate against ECR to access the provided image.
func GetGCRAuthConfig(ctx context.Context, authOptions *auth.AuthOptions) (authn.AuthConfig, time.Duration, error) {
	var authConfig authn.AuthConfig
	var expiresIn time.Duration

	provider := NewProvider()
	saToken, err := provider.GetWorkloadIdentityToken(ctx)
	if err != nil {
		return authConfig, expiresIn, err
	}

	authConfig = authn.AuthConfig{
		Username: "oauth2accesstoken",
		Password: saToken.AccessToken,
	}
	expiresIn = time.Duration(saToken.ExpiresIn)

	return authConfig, expiresIn, nil
}
