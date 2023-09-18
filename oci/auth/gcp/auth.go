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

package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/fluxcd/pkg/cache"
	"github.com/fluxcd/pkg/oci/auth"
)

type gceToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// GCP_TOKEN_URL is the default GCP metadata endpoint used for authentication.
const GCP_TOKEN_URL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

// ValidHost returns if a given host is a valid GCR host.
func ValidHost(host string) bool {
	return host == "gcr.io" || strings.HasSuffix(host, ".gcr.io") || strings.HasSuffix(host, "-docker.pkg.dev")
}

// Client is a GCP GCR client which can log into the registry and return
// authorization information.
type Client struct {
	tokenURL string
	cache    *cache.Cache
	mu       *sync.Mutex
}

var _ auth.Client = &Client{}

// NewClient creates a new GCR client with default configurations.
func NewClient() *Client {
	return &Client{tokenURL: GCP_TOKEN_URL}
}

// WithTokenURL sets the token URL used by the GCR client.
func (c *Client) WithTokenURL(url string) *Client {
	c.tokenURL = url
	return c
}

func (c *Client) WithCache(cache *cache.Cache) *Client {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = cache
	return c
}

// getLoginAuth obtains authentication by getting a token from the metadata API
// on GCP. This assumes that the pod has right to pull the image which would be
// the case if it is hosted on GCP. It works with both service account and
// workload identity enabled clusters.
func (c *Client) getLoginAuth(ctx context.Context) (authn.AuthConfig, time.Duration, error) {
	var authConfig authn.AuthConfig

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.tokenURL, nil)
	if err != nil {
		return authConfig, 0, err
	}

	request.Header.Add("Metadata-Flavor", "Google")

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return authConfig, 0, err
	}
	defer response.Body.Close()
	defer io.Copy(io.Discard, response.Body)

	if response.StatusCode != http.StatusOK {
		return authConfig, 0, fmt.Errorf("unexpected status from metadata service: %s", response.Status)
	}

	var accessToken gceToken
	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&accessToken); err != nil {
		return authConfig, 0, err
	}

	authConfig = authn.AuthConfig{
		Username: "oauth2accesstoken",
		Password: accessToken.AccessToken,
	}
	return authConfig, time.Duration(accessToken.ExpiresIn), nil
}

// getOrCacheLoginAuth returns the authentication material from the cache if
// found, or fetches it from upstream and caches it.
func (c *Client) getOrCacheLoginAuth(ctx context.Context) (authn.AuthConfig, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var authConfig authn.AuthConfig
	var err error
	var expiresIn time.Duration

	retrieved, ok := c.cache.Get(c.tokenURL)
	if ok {
		authConfig = retrieved.(authn.AuthConfig)
	} else {
		authConfig, expiresIn, err = c.getLoginAuth(ctx)
		if err != nil {
			return authConfig, err
		}
		c.cache.Set(c.tokenURL, authConfig, expiresIn)
	}
	return authConfig, nil
}

// Login attempts to get the authentication material for GCR. The caller can
// ensure that the passed image is a valid GCR image using ValidHost(). If the
// client is configured with a cache, then the authentication material is cached
// using the token URL as the key.
func (c *Client) Login(ctx context.Context, _ auth.AuthOptions) (authn.Authenticator, error) {
	var authConfig authn.AuthConfig
	var err error
	if c.cache == nil {
		authConfig, _, err = c.getLoginAuth(ctx)
	} else {
		authConfig, err = c.getOrCacheLoginAuth(ctx)
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

	c.cache.Delete(c.tokenURL)
	return nil
}

// OIDCLogin attempts to get the authentication material for GCR from the token url set in the client.
func (c *Client) OIDCLogin(ctx context.Context) (authn.Authenticator, error) {
	var authConfig authn.AuthConfig
	var err error
	if c.cache == nil {
		authConfig, _, err = c.getLoginAuth(ctx)
	} else {
		authConfig, err = c.getOrCacheLoginAuth(ctx)
	}
	if err != nil {
		log.FromContext(ctx).Info("error logging into GCP " + err.Error())
		return nil, err
	}

	auth := authn.FromConfig(authConfig)
	return auth, nil
}
