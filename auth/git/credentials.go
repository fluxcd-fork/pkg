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

package git

//import (
//"context"
//"fmt"
//"time"

//"github.com/fluxcd/pkg/auth"
//"github.com/fluxcd/pkg/auth/azure"
//"github.com/fluxcd/pkg/auth/gcp"
//)

//// Credentials contains the various authentication data needed
//// in order to access a Git repository.
//type Credentials struct {
//Username    string
//Password    string
//BearerToken string
//}

//// GetCredentials returns a Credentials object that contains the authentication
//// data needed to access the Git repository.
//// If `authOptions.CacheKey` isn't empty and caching has been enabled via
//// `auth.InitCache()`, then the cache key is used to cache the credentials.
//// The credentials are evicted from the cache after it's expiration time, as
//// advertised by the provider.
//func GetCredentials(ctx context.Context, provider string, authOptions *auth.AuthOptions) (*Credentials, error) {
//var creds Credentials
//var expiresIn time.Duration

//cache := auth.GetCache()
//if cache != nil && authOptions.CacheKey != "" {
//val, found := cache.Get(authOptions.CacheKey)
//if found {
//creds = val.(Credentials)
//return &creds, nil
//}
//}

//switch provider {
//case auth.AZURE_PROVIDER:
//provider := azure.NewProvider()
//armToken, err := provider.GetResourceManagerToken(ctx)
//if err != nil {
//return nil, err
//}
//creds = Credentials{
//BearerToken: armToken.Token,
//}
//expiresIn = armToken.ExpiresOn.UTC().Sub(time.Now().UTC())
//case auth.GCP_PROVIDER:
//provider := gcp.NewProvider()
//saToken, err := provider.GetServiceAccountToken(ctx)
//if err != nil {
//return nil, err
//}

//creds = Credentials{
//Password: saToken.AccessToken,
//}
//// If a Secret has been provided then try to extract the service account
//// email from it and use that as the username.
//if authOptions != nil && authOptions.Secret != nil {
//creds.Username = string(authOptions.Secret.Data["client_email"])
//}

//expiresIn = time.Duration(saToken.ExpiresIn)
//default:
//return nil, fmt.Errorf("unkown provider: %s", provider)
//}

//if cache != nil && authOptions.CacheKey != "" {
//if err := cache.Set(authOptions.CacheKey, creds, expiresIn); err != nil {
//return nil, err
//}
//}
//return &creds, nil
//}
