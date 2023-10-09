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

package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// GCP_TOKEN_URL is the default GCP metadata endpoint used for authentication.
const GCP_TOKEN_URL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

// Provider is an authentication provider for GCP.
type Provider struct {
	tokenURL string
}

type ProviderOptFunc func(*Provider)

func NewProvider(opts ...ProviderOptFunc) *Provider {
	p := &Provider{}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func WithTokenURL(tokenURL string) ProviderOptFunc {
	return func(p *Provider) {
		p.tokenURL = tokenURL
	}
}

// ServiceAccountToken is the object returned by the GKE metadata server
// upon requesting for a GCP service account token.
// Ref: https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity#metadata_server
type ServiceAccountToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// GetServiceAccountToken fetches the access token for the service account
// that the Pod is configured to run as, using Workload Identity.
// Ref: https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity
// The Kubernetes service account must be bound to a GCP service account with
// the appropriate permissions.
func (p *Provider) GetServiceAccountToken(ctx context.Context) (*ServiceAccountToken, error) {
	if p.tokenURL == "" {
		p.tokenURL = GCP_TOKEN_URL
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, p.tokenURL, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Metadata-Flavor", "Google")

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	defer io.Copy(io.Discard, response.Body)

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status from metadata service: %s", response.Status)
	}

	var accessToken ServiceAccountToken
	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&accessToken); err != nil {
		return nil, err
	}

	return &accessToken, nil
}
