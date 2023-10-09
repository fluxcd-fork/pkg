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

package azure

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	_ "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	. "github.com/onsi/gomega"
)

func TestGetResourceManagerToken(t *testing.T) {
	tests := []struct {
		name      string
		tokenCred azcore.TokenCredential
		opts      []ProviderOptFunc
		want      string
		wantErr   error
	}{
		{
			name: "default scope",
			tokenCred: &fakeTokenCredential{
				token: "foo",
			},
			// https://github.com/Azure/azure-sdk-for-go/blob/dd448cf29c643578b23016ca24bdc2316bd70931/sdk/azcore/arm/runtime/runtime.go#L22
			want: "foo-https://management.azure.com/.default",
		},
		{
			name: "custom scope",
			tokenCred: &fakeTokenCredential{
				token: "foo",
			},
			opts: []ProviderOptFunc{WithAzureGovtScope()},
			// https://github.com/Azure/azure-sdk-for-go/blob/dd448cf29c643578b23016ca24bdc2316bd70931/sdk/azcore/arm/runtime/runtime.go#L18
			want: "foo-https://management.usgovcloudapi.net/.default",
		},
		{
			name: "error",
			tokenCred: &fakeTokenCredential{
				err: errors.New("oh no!"),
			},
			wantErr: errors.New("oh no!"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			provider := NewProvider(tt.opts...)
			provider.credential = tt.tokenCred
			token, err := provider.GetResourceManagerToken(context.TODO())
			if tt.wantErr != nil {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err).To(Equal(errors.New("oh no!")))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(token.Token).To(Equal(tt.want))
			}
		})
	}
}

type fakeTokenCredential struct {
	token     string
	expiresOn time.Time
	err       error
}

var _ azcore.TokenCredential = &fakeTokenCredential{}

func (tc *fakeTokenCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if tc.err != nil {
		return azcore.AccessToken{}, tc.err
	}
	return azcore.AccessToken{Token: fmt.Sprintf("%s-%s", tc.token, options.Scopes[0]), ExpiresOn: tc.expiresOn}, nil
}
