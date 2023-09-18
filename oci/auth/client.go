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

package auth

import (
	"context"

	"github.com/google/go-containerregistry/pkg/authn"
)

// AuthOptions specifies options for authetnication.
type AuthOptions struct {
	RegistryURL string
}

// Client knows how to login and logout of a registry.
type Client interface {
	// Login logs into a registry using the provided auth options. Depending on
	// the client and the cloud registry, the login operation could be done via
	// Workoad Identity/IMDS/OIDC. If the client is configured with a cache, then the
	// authentication config is cached.
	Login(ctx context.Context, opts AuthOptions) (authn.Authenticator, error)
	// Logout evicts the authentication config for the provided auth options
	// from the cache. Its a no-op if the client doesn't have a cache.
	Logout(opts AuthOptions) error
}
