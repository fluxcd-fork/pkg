/*
Copyright 2022 The Flux authors

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

package azure

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	_ "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/google/go-containerregistry/pkg/authn"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/fluxcd/pkg/cache"
	"github.com/fluxcd/pkg/oci/auth"
)

// Client is an Azure ACR client which can log into the registry and return
// authorization information.
type Client struct {
	credential azcore.TokenCredential
	cache      *cache.Cache
	scheme     string
	mu         sync.Mutex
}

var _ auth.Client = &Client{}

// NewClient creates a new ACR client with default configurations.
func NewClient() *Client {
	return &Client{scheme: "https"}
}

// WithTokenCredential sets the token credential used by the ACR client.
func (c *Client) WithTokenCredential(tc azcore.TokenCredential) *Client {
	c.credential = tc
	return c
}

// WithScheme sets the scheme of the http request that the client makes.
func (c *Client) WithScheme(scheme string) *Client {
	c.scheme = scheme
	return c
}

func (c *Client) WithCache(cache *cache.Cache) *Client {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = cache
	return c
}

// getLoginAuth returns authentication for ACR. The details needed for authentication
// are gotten from environment variable so there is no need to mount a host path.
// The endpoint is the registry server and will be queried for OAuth authorization token.
func (c *Client) getLoginAuth(ctx context.Context, registryURL string) (authn.AuthConfig, time.Duration, error) {
	var authConfig authn.AuthConfig

	// Use default credentials if no token credential is provided.
	// NOTE: NewDefaultAzureCredential() performs a lot of environment lookup
	// for creating default token credential. Load it only when it's needed.
	if c.credential == nil {
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return authConfig, 0, err
		}
		c.credential = cred
	}

	configurationEnvironment := getCloudConfiguration(registryURL)
	// Obtain access token using the token credential.
	armToken, err := c.credential.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{configurationEnvironment.Services[cloud.ResourceManager].Endpoint + "/" + ".default"},
	})
	if err != nil {
		return authConfig, 0, err
	}

	// Obtain ACR access token using exchanger.
	ex := newExchanger(registryURL)
	accessToken, err := ex.ExchangeACRAccessToken(string(armToken.Token))
	if err != nil {
		return authConfig, 0, fmt.Errorf("error exchanging token: %w", err)
	}

	return authn.AuthConfig{
		// This is the acr username used by Azure
		// See documentation: https://docs.microsoft.com/en-us/azure/container-registry/container-registry-authentication?tabs=azure-cli#az-acr-login-with---expose-token
		Username: "00000000-0000-0000-0000-000000000000",
		Password: accessToken,
	}, time.Hour * 3, nil
}

// getOrCacheLoginAuth returns the authentication material from the cache if
// found, or fetches it from upstream and caches it.
func (c *Client) getOrCacheLoginAuth(ctx context.Context, registryURL string) (authn.AuthConfig, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var authConfig authn.AuthConfig
	var err error
	var expiresIn time.Duration

	retrieved, ok := c.cache.Get(registryURL)
	if ok {
		authConfig = retrieved.(authn.AuthConfig)
	} else {
		authConfig, expiresIn, err = c.getLoginAuth(ctx, registryURL)
		if err != nil {
			return authConfig, err
		}
		c.cache.Set(registryURL, authConfig, expiresIn)
	}
	return authConfig, nil
}

// getCloudConfiguration returns the cloud configuration based on the registry URL.
// List from https://github.com/Azure/azure-sdk-for-go/blob/main/sdk/containers/azcontainerregistry/cloud_config.go#L16
func getCloudConfiguration(url string) cloud.Configuration {
	switch {
	case strings.HasSuffix(url, ".azurecr.cn"):
		return cloud.AzureChina
	case strings.HasSuffix(url, ".azurecr.us"):
		return cloud.AzureGovernment
	default:
		return cloud.AzurePublic
	}
}

// ValidHost returns if a given host is a Azure container registry.
// List from https://github.com/kubernetes/kubernetes/blob/v1.23.1/pkg/credentialprovider/azure/azure_credentials.go#L55
func ValidHost(host string) bool {
	for _, v := range []string{".azurecr.io", ".azurecr.cn", ".azurecr.de", ".azurecr.us"} {
		if strings.HasSuffix(host, v) {
			return true
		}
	}
	return false
}

// Login attempts to get the authentication material for ACR. The caller can
// ensure that the passed image is a valid ACR image using ValidHost(). If the
// client is configured with a cache, then the authentication material is cached
// for a specific TTL as described by the registry server.
func (c *Client) Login(ctx context.Context, opts auth.AuthOptions) (authn.Authenticator, error) {
	var authConfig authn.AuthConfig
	var err error
	if c.cache == nil {
		authConfig, _, err = c.getLoginAuth(ctx, opts.RegistryURL)
	} else {
		authConfig, err = c.getOrCacheLoginAuth(ctx, opts.RegistryURL)
	}
	if err != nil {
		return nil, err
	}

	auth := authn.FromConfig(authConfig)
	return auth, nil
}

// Logout evicts the authentication material for the provided authentication
// options from the cache.
func (c *Client) Logout(opts auth.AuthOptions) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cache == nil {
		return nil
	}

	c.cache.Delete(opts.RegistryURL)
	return nil
}

// OIDCLogin attempts to get an Authenticator for the provided ACR registry URL endpoint.
//
// If you want to construct an Authenticator based on an image reference,
// you may want to use Login instead.
func (c *Client) OIDCLogin(ctx context.Context, registryUrl string) (authn.Authenticator, error) {
	var authConfig authn.AuthConfig
	var err error
	if c.cache == nil {
		authConfig, _, err = c.getLoginAuth(ctx, registryUrl)
	} else {
		authConfig, err = c.getOrCacheLoginAuth(ctx, registryUrl)
	}
	if err != nil {
		log.FromContext(ctx).Info("error logging into ACR " + err.Error())
		return nil, err
	}

	auth := authn.FromConfig(authConfig)
	return auth, nil
}
