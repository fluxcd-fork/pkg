/*
Copyright 2023 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"context"
	"net/url"
	"time"

	"github.com/fluxcd/pkg/auth/aws"
	"github.com/fluxcd/pkg/auth/azure"
	"github.com/fluxcd/pkg/auth/gcp"
	"github.com/fluxcd/pkg/auth/github"
	"github.com/fluxcd/pkg/git"
	"github.com/google/go-containerregistry/pkg/authn"
)

const (
	AwsProvider    = "aws"
	AzureProvider  = "azure"
	GcpProvider    = "gcp"
	GitHubProvider = "github"
)

const GitHubAccessTokenUsername = "x-access-token"

// Authenticator can provide authentication credentials for various resources
// on various cloud providers and SaaS.
type Authenticator struct {
	AzureOpts  []azure.ProviderOptFunc
	AwsOpts    []aws.ProviderOptFunc
	GcpOpts    []gcp.ProviderOptFunc
	GitHubOpts []github.ProviderOptFunc
}

// GetRegistryAuthenticator returns an authenticator that can provide
// credentials to access the provided registry. If caching is enabled and cacheKey
// is not blank, the credentials are cached according to the ttl advertised by
// the provider.
func (a *Authenticator) GetRegistryAuthenticator(ctx context.Context, registry string,
	provider string, cacheKey string) (authn.Authenticator, error) {
	var authConfig authn.AuthConfig
	if cache != nil && cacheKey != "" {
		val, found := cache.Get(cacheKey)
		if found {
			authConfig = val.(authn.AuthConfig)
			return authn.FromConfig(authConfig), nil
		}
	}

	var err error
	var expiresIn time.Duration
	switch provider {
	case AwsProvider:
		provider := aws.NewProvider(a.AwsOpts...)
		authConfig, expiresIn, err = provider.GetECRAuthConfig(ctx, registry)
	case AzureProvider:
		provider := azure.NewProvider(a.AzureOpts...)
		authConfig, expiresIn, err = provider.GetACRAuthConfig(ctx, registry)
	case GcpProvider:
		provider := gcp.NewProvider(a.GcpOpts...)
		authConfig, expiresIn, err = provider.GetGCRAuthConfig(ctx)
	default:
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if cache != nil && cacheKey != "" {
		if err := cache.Set(cacheKey, authConfig, expiresIn); err != nil {
			return nil, err
		}
	}

	return authn.FromConfig(authConfig), nil
}

// GetGitAuthOptions returns authentication options to access the provided
// Git repository. If caching is enabled and cacheKey is not blank, the
// credentials are cached according to the ttl advertised by the Git provider.
func (a *Authenticator) GetGitAuthOptions(ctx context.Context, repoURL url.URL,
	provider string, cacheKey string) (*git.AuthOptions, error) {
	if cache != nil && cacheKey != "" {
		val, found := cache.Get(cacheKey)
		if found {
			authOpts := val.(git.AuthOptions)
			return &authOpts, nil
		}
	}

	var authOpts *git.AuthOptions
	var expiresIn time.Duration
	switch provider {
	case AzureProvider:
		provider := azure.NewProvider(a.AzureOpts...)
		armToken, err := provider.GetResourceManagerToken(ctx)
		if err != nil {
			return nil, err
		}
		authOpts, err = git.NewAuthOptions(repoURL, map[string][]byte{
			"bearerToken": []byte(armToken.Token),
		})
		if err != nil {
			return nil, err
		}

		expiresIn = armToken.ExpiresOn.UTC().Sub(time.Now().UTC())
	case GcpProvider:
		provider := gcp.NewProvider(a.GcpOpts...)
		saToken, err := provider.GetServiceAccountToken(ctx)
		if err != nil {
			return nil, err
		}
		email, err := provider.GetServiceAccountEmail(ctx)
		if err != nil {
			return nil, err
		}

		authOpts, err = git.NewAuthOptions(repoURL, map[string][]byte{
			"password": []byte(saToken.AccessToken),
			"username": []byte(email),
		})

		expiresIn = time.Duration(saToken.ExpiresIn)
	case GitHubProvider:
		provider, err := github.NewProvider(a.GitHubOpts...)
		if err != nil {
			return nil, err
		}
		appToken, err := provider.GetAppToken(ctx)
		if err != nil {
			return nil, err
		}

		authOpts, err = git.NewAuthOptions(repoURL, map[string][]byte{
			"password": []byte(appToken.Token),
			"username": []byte(GitHubAccessTokenUsername),
		})
		if err != nil {
			return nil, err
		}
		expiresIn = appToken.ExpiresIn
	default:
		return nil, nil
	}

	if cache != nil && cacheKey != "" {
		if err := cache.Set(cacheKey, authOpts, expiresIn); err != nil {
			return nil, err
		}
	}
	return authOpts, nil
}
