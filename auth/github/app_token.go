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

package github

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	corev1 "k8s.io/api/core/v1"
)

const (
	appIDKey          = "appID"
	installationIDKey = "installationID"
	pkKey             = "privateKey"
	apiURLKey         = "apiURL"
)

type Provider struct {
	apiURL         string
	privateKey     []byte
	appID          int
	installationID int
	transport      http.RoundTripper
}

type ProviderOptFunc func(*Provider) error

func NewProvider(opts ...ProviderOptFunc) (*Provider, error) {
	p := &Provider{}
	for _, opt := range opts {
		err := opt(p)
		if err != nil {
			return nil, err
		}
	}
	return p, nil
}

func WithInstllationID(installationID int) ProviderOptFunc {
	return func(p *Provider) error {
		p.installationID = installationID
		return nil
	}
}

func WithAppID(appID int) ProviderOptFunc {
	return func(p *Provider) error {
		p.appID = appID
		return nil
	}
}

func WithPrivateKey(pk []byte) ProviderOptFunc {
	return func(p *Provider) error {
		p.privateKey = pk
		return nil
	}
}

func WithApiURL(apiURL string) ProviderOptFunc {
	return func(p *Provider) error {
		p.apiURL = apiURL
		return nil
	}
}

func WithTransport(t http.RoundTripper) ProviderOptFunc {
	return func(p *Provider) error {
		p.transport = t
		return nil
	}
}

func WithSecret(secret corev1.Secret) ProviderOptFunc {
	return func(p *Provider) error {
		var err error
		p.appID, err = strconv.Atoi(string(secret.Data[appIDKey]))
		if err != nil {
			return err
		}
		p.installationID, err = strconv.Atoi(string(secret.Data[installationIDKey]))
		if err != nil {
			return err
		}
		p.privateKey = secret.Data[pkKey]
		p.apiURL = string(secret.Data[apiURLKey])
		return nil
	}
}

type AppToken struct {
	Token     string
	ExpiresIn time.Duration
}

func (p *Provider) GetAppToken(ctx context.Context) (*AppToken, error) {
	if p.transport == nil {
		p.transport = http.DefaultTransport
	}

	ghTransport, err := ghinstallation.New(p.transport, int64(p.appID), int64(p.installationID), p.privateKey)
	if err != nil {
		return nil, err
	}
	if p.apiURL != "" {
		ghTransport.BaseURL = p.apiURL
	}

	token, err := ghTransport.Token(ctx)
	if err != nil {
		return nil, err
	}
	expiresAt, _, err := ghTransport.Expiry()
	if err != nil {
		return nil, err
	}
	return &AppToken{
		Token:     token,
		ExpiresIn: expiresAt.UTC().Sub(time.Now().UTC()),
	}, nil
}
