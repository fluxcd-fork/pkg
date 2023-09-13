package aws

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/google/go-containerregistry/pkg/authn"

	"github.com/fluxcd/pkg/auth"
)

var registryPartRe = regexp.MustCompile(`([0-9+]*).dkr.ecr.([^/.]*)\.(amazonaws\.com[.cn]*)`)

// ParseRegistry returns the AWS account ID and region and `true` if
// the image registry/repository is hosted in AWS's Elastic Container Registry,
// otherwise empty strings and `false`.
func ParseRegistry(registry string) (accountId, awsEcrRegion string, ok bool) {
	registryParts := registryPartRe.FindAllStringSubmatch(registry, -1)
	if len(registryParts) < 1 || len(registryParts[0]) < 3 {
		return "", "", false
	}
	return registryParts[0][1], registryParts[0][2], true
}

// GetECRAuthConfig returns an AuthConfig that contains the credentials
// required to authenticate against ECR to access the provided image.
func GetECRAuthConfig(ctx context.Context, image string, authOptions *auth.AuthOptions) (authn.AuthConfig, time.Duration, error) {
	var authConfig authn.AuthConfig
	var expiresIn time.Duration
	_, awsEcrRegion, ok := ParseRegistry(image)
	if !ok {
		return authConfig, expiresIn, errors.New("failed to parse AWS ECR image, invalid ECR image")
	}

	provider := NewProvider(WithRegion(awsEcrRegion))
	cfg, err := provider.GetConfig(ctx)
	if err != nil {
		return authConfig, expiresIn, err
	}

	ecrService := ecr.NewFromConfig(cfg)
	// NOTE: ecr.GetAuthorizationTokenInput has deprecated RegistryIds. Hence,
	// pass nil input.
	ecrToken, err := ecrService.GetAuthorizationToken(ctx, nil)
	if err != nil {
		return authConfig, expiresIn, err
	}

	// Validate the authorization data.
	if len(ecrToken.AuthorizationData) == 0 {
		return authConfig, expiresIn, errors.New("no authorization data")
	}
	authData := ecrToken.AuthorizationData[0]
	if authData.AuthorizationToken == nil {
		return authConfig, expiresIn, fmt.Errorf("no authorization token")
	}
	token, err := base64.StdEncoding.DecodeString(*authData.AuthorizationToken)
	if err != nil {
		return authConfig, expiresIn, err
	}

	tokenSplit := strings.Split(string(token), ":")
	// Validate the tokens.
	if len(tokenSplit) != 2 {
		return authConfig, expiresIn, fmt.Errorf("invalid authorization token, expected the token to have two parts separated by ':', got %d parts", len(tokenSplit))
	}

	authConfig = authn.AuthConfig{
		Username: tokenSplit[0],
		Password: tokenSplit[1],
	}
	expiresIn = authData.ExpiresAt.Sub(time.Now())

	return authConfig, expiresIn, nil
}
