// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	josev3 "github.com/go-jose/go-jose/v3"
	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	servercrypto "github.com/stacklok/toolhive/pkg/authserver/server/crypto"
)

// newExpiryTestStore returns a store with a private_key_jwt client and the key
// that signs for it.
func newExpiryTestStore(t *testing.T) (*assertionStore, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &assertionStore{
		seen: map[string]struct{}{},
		client: &fosite.DefaultOpenIDConnectClient{
			DefaultClient: &fosite.DefaultClient{ID: assertionTestClientID},
			JSONWebKeys: &josev3.JSONWebKeySet{Keys: []josev3.JSONWebKey{{
				Key: &key.PublicKey, KeyID: assertionTestKeyID, Use: "sig", Algorithm: "ES256",
			}}},
			TokenEndpointAuthMethod:           "private_key_jwt",
			TokenEndpointAuthSigningAlgorithm: "ES256",
		},
	}, key
}

func assertionForm(assertion string) url.Values {
	return url.Values{
		"client_assertion_type": {privateKeyJWTAssertionType},
		"client_assertion":      {assertion},
	}
}

func TestClientAssertionExpiryStrategy(t *testing.T) {
	t.Parallel()

	now := time.Now()
	tests := []struct {
		name     string
		expiry   *jwt.NumericDate
		wantHint string // empty when the assertion is accepted
	}{
		{name: "exp in the future", expiry: jwt.NewNumericDate(now.Add(time.Minute))},
		{name: "exp of zero", expiry: jwt.NewNumericDate(time.Unix(0, 0)), wantHint: "positive 'exp'"},
		{
			name: "exp of the maximum int64",
			expiry: func() *jwt.NumericDate {
				exp := jwt.NumericDate(math.MaxInt64)
				return &exp
			}(),
			wantHint: "could not be read",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store, key := newExpiryTestStore(t)
			cfg := &fosite.Config{AccessTokenIssuer: assertionTestIssuer, TokenURL: assertionTestTokenURL}
			provider := fosite.NewOAuth2Provider(store, newClientAssertionAudienceConfig(cfg))
			strategy := newClientAssertionErrorStrategy(
				newClientAssertionExpiryStrategy(provider.DefaultClientAuthenticationStrategy))

			assertion := signAssertion(t, key, assertionTestKeyID, jwt.Claims{
				Issuer:   assertionTestClientID,
				Subject:  assertionTestClientID,
				Audience: jwt.Audience{assertionTestTokenURL},
				ID:       "jti-" + tt.name,
				IssuedAt: jwt.NewNumericDate(now),
				Expiry:   tt.expiry,
			})
			form := assertionForm(assertion)
			req := httptest.NewRequest(http.MethodPost, assertionTestTokenURL, strings.NewReader(form.Encode()))
			client, err := strategy(context.Background(), req, form)

			if tt.wantHint == "" {
				require.NoError(t, err)
				assert.Equal(t, assertionTestClientID, client.GetID())
				return
			}
			var rfcErr *fosite.RFC6749Error
			require.ErrorAs(t, err, &rfcErr)
			assert.Equal(t, fosite.ErrInvalidClient.ErrorField, rfcErr.ErrorField)
			assert.Equal(t, http.StatusUnauthorized, rfcErr.CodeField)
			assert.Contains(t, rfcErr.HintField, tt.wantHint)
		})
	}
}

// TestClientAssertionExpiryStrategy_ReadsLikeFosite pins that the exp check
// does not refuse a signed assertion that fosite accepts: it reads the claims
// as fosite does, so these odd but accepted forms keep authenticating.
func TestClientAssertionExpiryStrategy_ReadsLikeFosite(t *testing.T) {
	t.Parallel()

	now := time.Now()
	tests := []struct {
		name   string
		claims map[string]any                // merged over valid claims
		wrap   func(assertion string) string // changes the serialized assertion
	}{
		{name: "trailing space", wrap: func(a string) string { return a + " " }},
		{name: "space inside", wrap: func(a string) string { return a[:10] + " " + a[10:] }},
		{name: "iat as a string", claims: map[string]any{"iat": "1700000000"}},
		{name: "nbf as a bool", claims: map[string]any{"nbf": true}},
		{name: "aud with a non-string member", claims: map[string]any{"aud": []any{assertionTestTokenURL, 5}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store, key := newExpiryTestStore(t)
			cfg := &fosite.Config{AccessTokenIssuer: assertionTestIssuer, TokenURL: assertionTestTokenURL}
			provider := fosite.NewOAuth2Provider(store, newClientAssertionAudienceConfig(cfg))
			strategy := newClientAssertionErrorStrategy(
				newClientAssertionExpiryStrategy(provider.DefaultClientAuthenticationStrategy))

			claims := map[string]any{
				"iss": assertionTestClientID,
				"sub": assertionTestClientID,
				"aud": assertionTestTokenURL,
				"jti": "jti-" + tt.name,
				"exp": now.Add(time.Minute).Unix(),
			}
			for k, v := range tt.claims {
				claims[k] = v
			}
			signer, err := josev4.NewSigner(
				josev4.SigningKey{Algorithm: josev4.ES256, Key: key},
				(&josev4.SignerOptions{}).WithType("JWT").WithHeader(josev4.HeaderKey("kid"), assertionTestKeyID))
			require.NoError(t, err)
			assertion, err := jwt.Signed(signer).Claims(claims).Serialize()
			require.NoError(t, err)
			if tt.wrap != nil {
				assertion = tt.wrap(assertion)
			}

			form := assertionForm(assertion)
			req := httptest.NewRequest(http.MethodPost, assertionTestTokenURL, strings.NewReader(form.Encode()))
			client, err := strategy(context.Background(), req, form)

			require.NoError(t, err)
			assert.Equal(t, assertionTestClientID, client.GetID())
		})
	}
}

// TestNewAuthorizationServer_ClientAssertionExpiry pins that the provider
// installs the exp check on the strategy it hands to fosite.
func TestNewAuthorizationServer_ClientAssertionExpiry(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	config, err := NewAuthorizationServerConfig(&AuthorizationServerParams{
		Issuer:               assertionTestIssuer,
		AccessTokenLifespan:  time.Hour,
		RefreshTokenLifespan: 24 * time.Hour,
		AuthCodeLifespan:     10 * time.Minute,
		HMACSecrets:          servercrypto.NewHMACSecrets([]byte("test-secret-with-32-bytes-long!!")),
		SigningKeyID:         "key-1",
		SigningKeyAlgorithm:  "RS256",
		SigningKey:           rsaKey,
	})
	require.NoError(t, err)

	store, key := newExpiryTestStore(t)
	provider, err := NewAuthorizationServer(config, store, nil)
	require.NoError(t, err)
	fositeProvider, ok := provider.(*fosite.Fosite)
	require.True(t, ok)

	assertion := signAssertion(t, key, assertionTestKeyID, jwt.Claims{
		Issuer:   assertionTestClientID,
		Subject:  assertionTestClientID,
		Audience: jwt.Audience{assertionTestTokenURL},
		ID:       "jti-provider",
		Expiry:   jwt.NewNumericDate(time.Unix(0, 0)),
	})
	form := assertionForm(assertion)
	req := httptest.NewRequest(http.MethodPost, assertionTestTokenURL, strings.NewReader(form.Encode()))
	_, err = fositeProvider.AuthenticateClient(context.Background(), req, form)

	var rfcErr *fosite.RFC6749Error
	require.ErrorAs(t, err, &rfcErr)
	assert.Equal(t, fosite.ErrInvalidClient.ErrorField, rfcErr.ErrorField)
}
