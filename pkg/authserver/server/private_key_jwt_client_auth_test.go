// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
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

const assertionTestOtherClientID = "other-client"

// assertionHarness runs real fosite behind the clock skew strategy with a fake
// store, so a change in fosite's check order or messages fails these tests.
type assertionHarness struct {
	key      *ecdsa.PrivateKey
	otherKey *ecdsa.PrivateKey // signs for assertionTestOtherClientID
	store    *assertionStore
	strategy fosite.ClientAuthenticationStrategy
	now      time.Time
}

func newAssertionClient(id string, key *ecdsa.PrivateKey) *fosite.DefaultOpenIDConnectClient {
	return &fosite.DefaultOpenIDConnectClient{
		DefaultClient: &fosite.DefaultClient{ID: id},
		JSONWebKeys: &josev3.JSONWebKeySet{Keys: []josev3.JSONWebKey{{
			Key: &key.PublicKey, KeyID: assertionTestKeyID, Use: "sig", Algorithm: "ES256",
		}}},
		TokenEndpointAuthMethod:           "private_key_jwt",
		TokenEndpointAuthSigningAlgorithm: "ES256",
	}
}

func newAssertionHarness(t *testing.T, mutateClient func(*fosite.DefaultOpenIDConnectClient)) *assertionHarness {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := newAssertionClient(assertionTestClientID, key)
	if mutateClient != nil {
		mutateClient(client)
	}
	store := &assertionStore{
		seen:   map[string]struct{}{},
		setExp: map[string]time.Time{},
		clients: map[string]fosite.Client{
			assertionTestClientID:      client,
			assertionTestOtherClientID: newAssertionClient(assertionTestOtherClientID, otherKey),
		},
	}
	cfg := &fosite.Config{AccessTokenIssuer: assertionTestIssuer, TokenURL: assertionTestTokenURL}
	provider := fosite.NewOAuth2Provider(store, newClientAssertionAudienceConfig(cfg))
	h := &assertionHarness{key: key, otherKey: otherKey, store: store, now: time.Now()}
	h.strategy = newClientAssertionErrorStrategy(newClientAssertionClockSkewStrategy(
		provider.DefaultClientAuthenticationStrategy, store, clientAssertionAudiences(cfg),
		func() time.Time { return h.now }, true))
	return h
}

func (h *assertionHarness) claims(jti string) jwt.Claims {
	return jwt.Claims{
		Issuer:   assertionTestClientID,
		Subject:  assertionTestClientID,
		Audience: jwt.Audience{assertionTestTokenURL},
		ID:       jti,
		IssuedAt: jwt.NewNumericDate(h.now),
		Expiry:   jwt.NewNumericDate(h.now.Add(time.Minute)),
	}
}

// skewIAT sets iat 30s ahead, which fosite refuses, so the assertion goes through the fallback.
func (h *assertionHarness) skewIAT(c *jwt.Claims) {
	c.IssuedAt = jwt.NewNumericDate(h.now.Add(30 * time.Second))
}

// authenticate signs the default claims, after mutate, and runs the strategy.
// extra sets further form values.
func (h *assertionHarness) authenticate(
	t *testing.T, jti string, mutate func(*jwt.Claims), extra url.Values,
) (fosite.Client, error) {
	t.Helper()
	claims := h.claims(jti)
	if mutate != nil {
		mutate(&claims)
	}
	return h.authenticateAssertion(t, signAssertion(t, h.key, assertionTestKeyID, claims), extra)
}

func (h *assertionHarness) authenticateAssertion(
	t *testing.T, assertion string, extra url.Values,
) (fosite.Client, error) {
	t.Helper()
	form := url.Values{
		"client_assertion_type": {privateKeyJWTAssertionType},
		"client_assertion":      {assertion},
	}
	for k, v := range extra {
		form[k] = v
	}
	req := httptest.NewRequest(http.MethodPost, assertionTestTokenURL, strings.NewReader(form.Encode()))
	return h.strategy(context.Background(), req, form)
}

func requireInvalidClient(t *testing.T, err error) *fosite.RFC6749Error {
	t.Helper()
	var rfcErr *fosite.RFC6749Error
	require.ErrorAs(t, err, &rfcErr)
	assert.Equal(t, fosite.ErrInvalidClient.ErrorField, rfcErr.ErrorField)
	assert.Equal(t, http.StatusUnauthorized, rfcErr.CodeField)
	return rfcErr
}

func TestClientAssertionClockSkew(t *testing.T) {
	t.Parallel()

	const (
		timeHint     = "check the iat, nbf and exp values"
		lifetimeHint = "positive 'exp' and a lifetime"
	)
	at := func(h *assertionHarness, offset time.Duration) *jwt.NumericDate {
		return jwt.NewNumericDate(h.now.Add(offset))
	}
	// shifted sets iat to now+offset with the default one minute lifetime.
	shifted := func(offset time.Duration) func(h *assertionHarness, c *jwt.Claims) {
		return func(h *assertionHarness, c *jwt.Claims) {
			c.IssuedAt = at(h, offset)
			c.Expiry = at(h, offset+time.Minute)
		}
	}
	maxLife := MaxAssertionLifespan

	tests := []struct {
		name   string
		mutate func(h *assertionHarness, c *jwt.Claims)
		extra  url.Values
		// wantOK means authentication succeeds, and a second use of the same
		// assertion is refused as a replay. Otherwise wantHint is a substring
		// of the refusal's hint.
		wantOK   bool
		wantHint string
	}{
		{name: "iat 60s ahead", mutate: shifted(60 * time.Second), wantOK: true},
		{name: "iat 61s ahead", mutate: shifted(61 * time.Second), wantHint: timeHint},
		{
			name: "iat outside the margin is reported before an over-long lifetime",
			mutate: func(h *assertionHarness, c *jwt.Claims) {
				c.IssuedAt = at(h, 61*time.Second)
				c.Expiry = at(h, 61*time.Second+maxLife+time.Second)
			},
			wantHint: timeHint,
		},
		{
			name: "exp outside the margin is reported before an over-long lifetime",
			mutate: func(h *assertionHarness, c *jwt.Claims) {
				c.Expiry = at(h, -2*time.Minute)
				c.IssuedAt = at(h, -2*time.Minute-maxLife-time.Minute)
			},
			wantHint: timeHint,
		},
		{
			name: "exp 59s ago",
			mutate: func(h *assertionHarness, c *jwt.Claims) {
				c.IssuedAt = at(h, -3*time.Minute)
				c.Expiry = at(h, -59*time.Second)
			},
			wantOK: true,
		},
		{
			name: "exp 60s ago",
			mutate: func(h *assertionHarness, c *jwt.Claims) {
				c.IssuedAt = at(h, -3*time.Minute)
				c.Expiry = at(h, -60*time.Second)
			},
			wantHint: timeHint,
		},
		{
			name:   "nbf 60s ahead",
			mutate: func(h *assertionHarness, c *jwt.Claims) { c.NotBefore = at(h, 60*time.Second) },
			wantOK: true,
		},
		{
			name:     "nbf 61s ahead",
			mutate:   func(h *assertionHarness, c *jwt.Claims) { c.NotBefore = at(h, 61*time.Second) },
			wantHint: timeHint,
		},
		{
			name: "lifetime one second above the maximum with a skewed iat",
			mutate: func(h *assertionHarness, c *jwt.Claims) {
				c.IssuedAt = at(h, 30*time.Second)
				c.Expiry = at(h, 30*time.Second+maxLife+time.Second)
			},
			wantHint: lifetimeHint,
		},
		{
			name: "lifetime of the maximum with a skewed iat",
			mutate: func(h *assertionHarness, c *jwt.Claims) {
				c.IssuedAt = at(h, 30*time.Second)
				c.Expiry = at(h, 30*time.Second+maxLife)
			},
			wantOK: true,
		},
		{
			name:     "lifetime above the maximum without skew",
			mutate:   func(h *assertionHarness, c *jwt.Claims) { c.Expiry = at(h, maxLife+time.Minute) },
			wantHint: lifetimeHint,
		},
		{
			name: "exp before iat",
			mutate: func(h *assertionHarness, c *jwt.Claims) {
				c.IssuedAt = at(h, 30*time.Second)
				c.Expiry = at(h, 20*time.Second)
			},
			wantHint: lifetimeHint,
		},
		{
			name:     "exp of zero",
			mutate:   func(_ *assertionHarness, c *jwt.Claims) { c.Expiry = jwt.NewNumericDate(time.Unix(0, 0)) },
			wantHint: lifetimeHint,
		},
		{
			name: "exp of the maximum int64",
			mutate: func(_ *assertionHarness, c *jwt.Claims) {
				exp := jwt.NumericDate(math.MaxInt64)
				c.Expiry = &exp
			},
			wantHint: "could not be read",
		},
		{
			name: "missing iat with exp inside the maximum from now",
			mutate: func(h *assertionHarness, c *jwt.Claims) {
				c.IssuedAt = nil
				c.Expiry = at(h, maxLife-10*time.Second)
			},
			wantOK: true,
		},
		{
			name: "missing iat with exp beyond the maximum from now",
			mutate: func(h *assertionHarness, c *jwt.Claims) {
				c.IssuedAt = nil
				c.Expiry = at(h, maxLife+time.Minute)
			},
			wantHint: lifetimeHint,
		},
		{
			name: "missing iat with a skewed nbf",
			mutate: func(h *assertionHarness, c *jwt.Claims) {
				c.IssuedAt = nil
				c.NotBefore = at(h, 30*time.Second)
			},
			wantOK: true,
		},
		{
			name: "missing iat with a skewed nbf and exp beyond the maximum from now",
			mutate: func(h *assertionHarness, c *jwt.Claims) {
				c.IssuedAt = nil
				c.NotBefore = at(h, 30*time.Second)
				c.Expiry = at(h, maxLife+30*time.Second)
			},
			wantHint: lifetimeHint,
		},
		{
			name: "iat of zero is treated as absent",
			mutate: func(h *assertionHarness, c *jwt.Claims) {
				c.IssuedAt = jwt.NewNumericDate(time.Unix(0, 0))
				c.NotBefore = at(h, 30*time.Second)
				c.Expiry = at(h, 2*time.Minute)
			},
			wantOK: true,
		},
		{
			name: "skewed assertion with the issuer as audience",
			mutate: func(h *assertionHarness, c *jwt.Claims) {
				h.skewIAT(c)
				c.Audience = jwt.Audience{"https://other.example.com", assertionTestIssuer}
			},
			wantOK: true,
		},
		{
			name: "skewed assertion with another audience",
			mutate: func(h *assertionHarness, c *jwt.Claims) {
				h.skewIAT(c)
				c.Audience = jwt.Audience{"https://elsewhere.example.com"}
			},
			wantHint: "Claim 'audience'",
		},
		{
			name: "skewed assertion with another issuer",
			mutate: func(h *assertionHarness, c *jwt.Claims) {
				h.skewIAT(c)
				c.Issuer = "someone-else"
			},
			wantHint: "Claim 'iss'",
		},
		{
			name: "skewed assertion with another subject",
			mutate: func(h *assertionHarness, c *jwt.Claims) {
				h.skewIAT(c)
				c.Subject = "someone-else"
			},
			extra:    url.Values{"client_id": {assertionTestClientID}},
			wantHint: "Claim 'sub'",
		},
		{
			name: "skewed assertion without a jti",
			mutate: func(h *assertionHarness, c *jwt.Claims) {
				h.skewIAT(c)
				c.ID = ""
			},
			wantHint: "Claim 'jti'",
		},
		{
			name:   "skewed assertion with the client_id in the form",
			mutate: (*assertionHarness).skewIAT,
			extra:  url.Values{"client_id": {assertionTestClientID}},
			wantOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newAssertionHarness(t, nil)
			jti := "jti-" + tt.name
			mutate := func(c *jwt.Claims) { tt.mutate(h, c) }

			client, err := h.authenticate(t, jti, mutate, tt.extra)
			if !tt.wantOK {
				require.Error(t, err)
				rfcErr := requireInvalidClient(t, err)
				assert.Contains(t, rfcErr.HintField, tt.wantHint)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, assertionTestClientID, client.GetID())

			claims := h.claims(jti)
			mutate(&claims)
			assert.Equal(t, claims.Expiry.Time(), h.store.setExp[jti], "the assertion's own exp is recorded")

			_, err = h.authenticate(t, jti, mutate, tt.extra)
			require.Error(t, err)
			requireInvalidClient(t, err)
		})
	}
}

// TestClientAssertionClockSkew_ReadsLikeFosite pins that the checks on an
// assertion fosite accepted do not refuse these odd but accepted forms: the
// claims are read as fosite reads them, not with a stricter parser.
func TestClientAssertionClockSkew_ReadsLikeFosite(t *testing.T) {
	t.Parallel()

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
			h := newAssertionHarness(t, nil)
			claims := map[string]any{
				"iss": assertionTestClientID,
				"sub": assertionTestClientID,
				"aud": assertionTestTokenURL,
				"jti": "jti-" + tt.name,
				"exp": h.now.Add(time.Minute).Unix(),
			}
			for k, v := range tt.claims {
				claims[k] = v
			}
			signer, err := josev4.NewSigner(
				josev4.SigningKey{Algorithm: josev4.ES256, Key: h.key},
				(&josev4.SignerOptions{}).WithType("JWT").WithHeader(josev4.HeaderKey("kid"), assertionTestKeyID))
			require.NoError(t, err)
			assertion, err := jwt.Signed(signer).Claims(claims).Serialize()
			require.NoError(t, err)
			if tt.wrap != nil {
				assertion = tt.wrap(assertion)
			}

			client, err := h.authenticateAssertion(t, assertion, nil)

			require.NoError(t, err)
			assert.Equal(t, assertionTestClientID, client.GetID())
		})
	}
}

func TestClientAssertionClockSkew_FallbackRefusals(t *testing.T) {
	t.Parallel()

	t.Run("a jti used before is refused inside the margin", func(t *testing.T) {
		t.Parallel()
		h := newAssertionHarness(t, nil)
		h.store.seen["jti-used"] = struct{}{}

		_, err := h.authenticate(t, "jti-used", func(c *jwt.Claims) {
			c.IssuedAt = jwt.NewNumericDate(h.now.Add(-90 * time.Second))
			c.Expiry = jwt.NewNumericDate(h.now.Add(-30 * time.Second))
		}, nil)
		require.Error(t, err)
		assert.Contains(t, requireInvalidClient(t, err).HintField, "MUST only be used once")
	})

	t.Run("a failed client lookup does not burn the jti", func(t *testing.T) {
		t.Parallel()
		h := newAssertionHarness(t, nil)
		h.store.getClientErr = errors.New("database unavailable")

		_, err := h.authenticate(t, "jti-lookup", h.skewIAT, nil)
		require.Error(t, err)
		assert.NotContains(t, requireInvalidClient(t, err).HintField, "iat", "the lookup failure must not blame the timestamps")
		require.Equal(t, 2, h.store.getClientCalls, "fosite's lookup and the fallback's lookup")
		assert.Zero(t, h.store.validCalls, "the jti must not be reserved before the client is known")
		assert.Empty(t, h.store.seen)
	})

	t.Run("the time claims are judged again after a slow jti check", func(t *testing.T) {
		t.Parallel()
		h := newAssertionHarness(t, nil)
		h.store.onValid = func() { h.now = h.now.Add(40 * time.Second) }

		// exp is 30s ago, inside the margin when the fallback starts and 70s ago
		// once the lookup and the jti check have taken 40s.
		_, err := h.authenticate(t, "jti-slow", func(c *jwt.Claims) {
			c.IssuedAt = jwt.NewNumericDate(h.now.Add(-90 * time.Second))
			c.Expiry = jwt.NewNumericDate(h.now.Add(-30 * time.Second))
		}, nil)
		require.Error(t, err)
		assert.Contains(t, requireInvalidClient(t, err).HintField, "iat, nbf and exp")
		assert.Empty(t, h.store.seen, "nothing is recorded for an assertion past the margin")
	})

	t.Run("an over-long jti is refused as invalid, not as reused", func(t *testing.T) {
		t.Parallel()
		h := newAssertionHarness(t, nil)
		h.store.validErr = errors.New("jti exceeds maximum length of 256 bytes")

		_, err := h.authenticate(t, strings.Repeat("j", MaxAssertionJTILength+1), h.skewIAT, nil)
		require.Error(t, err)
		hint := requireInvalidClient(t, err).HintField
		assert.Contains(t, hint, "is invalid")
		assert.NotContains(t, hint, "only be used once")
	})

	t.Run("client B cannot present an assertion that names client A", func(t *testing.T) {
		t.Parallel()
		h := newAssertionHarness(t, nil)
		claims := h.claims("jti-forged")
		h.skewIAT(&claims)
		forged := signAssertion(t, h.otherKey, assertionTestKeyID, claims)

		_, err := h.authenticateAssertion(t, forged, url.Values{"client_id": {assertionTestOtherClientID}})
		require.Error(t, err)
		assert.Contains(t, requireInvalidClient(t, err).HintField, "Claim 'iss'",
			"fosite verifies B's signature and hits the time error, so the fallback must refuse on iss")
		assert.Zero(t, h.store.validCalls)
		assert.Empty(t, h.store.seen)
	})

	laterClients := []struct {
		name  string
		build func(h *assertionHarness) fosite.Client
	}{
		{
			name: "a client that changed authentication method is refused",
			build: func(h *assertionHarness) fosite.Client {
				changed := newAssertionClient(assertionTestClientID, h.key)
				changed.TokenEndpointAuthMethod = "client_secret_basic"
				return changed
			},
		},
		{
			name: "a client that is no longer an OpenID Connect client is refused",
			build: func(*assertionHarness) fosite.Client {
				return &fosite.DefaultClient{ID: assertionTestClientID}
			},
		},
	}
	for _, tt := range laterClients {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newAssertionHarness(t, nil)
			h.store.laterClient = tt.build(h)

			_, err := h.authenticate(t, "jti-changed", h.skewIAT, nil)
			require.Error(t, err)
			assert.Contains(t, requireInvalidClient(t, err).HintField, "private_key_jwt")
			require.Equal(t, 2, h.store.getClientCalls, "fosite's lookup and the fallback's lookup")
			assert.Zero(t, h.store.validCalls)
			assert.Empty(t, h.store.seen)
		})
	}
}

func TestRecoverSkewedClientAssertion_UnreadableClaims(t *testing.T) {
	t.Parallel()

	store := &assertionStore{seen: map[string]struct{}{}, setExp: map[string]time.Time{}}
	fositeErr := fosite.ErrInvalidClient.WithHint("fosite's time error")
	form := url.Values{"client_id": {assertionTestClientID}}

	client, err := recoverSkewedClientAssertion(
		context.Background(), store, []string{assertionTestTokenURL}, form, "not-a-jwt", time.Now, fositeErr)

	require.Error(t, err)
	assert.Nil(t, client)
	assert.Equal(t, "The 'client_assertion' claims could not be read.", requireInvalidClient(t, err).HintField)
	assert.Zero(t, store.getClientCalls)
	assert.Zero(t, store.validCalls)
	assert.Empty(t, store.seen)
}

func TestClientAssertionClockSkew_StorageFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		configure func(*assertionStore)
	}{
		{
			name: "jti check failure is a server error",
			configure: func(s *assertionStore) {
				s.validErr = errors.New("redis: connection refused")
				s.recordValidErr = true
			},
		},
		{
			name: "failure to record the jti is a server error",
			configure: func(s *assertionStore) {
				s.setErr = errors.New("redis: connection refused")
				s.recordSetErr = true
			},
		},
	}

	paths := []struct {
		name   string
		mutate func(h *assertionHarness) func(*jwt.Claims)
	}{
		{name: "through the fallback", mutate: func(h *assertionHarness) func(*jwt.Claims) { return h.skewIAT }},
		{name: "on fosite's own path", mutate: func(*assertionHarness) func(*jwt.Claims) { return nil }},
	}

	for _, tt := range tests {
		for _, path := range paths {
			t.Run(tt.name+" "+path.name, func(t *testing.T) {
				t.Parallel()
				h := newAssertionHarness(t, nil)
				tt.configure(h.store)

				_, err := h.authenticate(t, "jti-storage", path.mutate(h), nil)
				var rfcErr *fosite.RFC6749Error
				require.ErrorAs(t, err, &rfcErr)
				assert.Equal(t, fosite.ErrServerError.ErrorField, rfcErr.ErrorField)
				assert.Equal(t, http.StatusInternalServerError, rfcErr.CodeField)
			})
		}
	}
}

// TestClientAssertionClockSkew_FositeOrder pins the order of fosite's checks
// that the fallback relies on: the signature, the client, its authentication
// method and the signing algorithm are all checked before the time claims, so
// an assertion that has a time problem and one of these problems never reaches
// the fallback. Each case asserts fosite's own hint for the non-time problem;
// the fallback re-checks the authentication method, so only that hint shows
// the refusal came from fosite. A fosite release that validates claims first
// fails these tests.
func TestClientAssertionClockSkew_FositeOrder(t *testing.T) {
	t.Parallel()

	expired := func(h *assertionHarness) func(*jwt.Claims) {
		return func(c *jwt.Claims) {
			c.IssuedAt = jwt.NewNumericDate(h.now.Add(-90 * time.Second))
			c.Expiry = jwt.NewNumericDate(h.now.Add(-30 * time.Second))
		}
	}

	tests := []struct {
		name         string
		mutateClient func(*fosite.DefaultOpenIDConnectClient)
		claims       func(h *assertionHarness) func(*jwt.Claims)
		sign         func(t *testing.T, h *assertionHarness, claims jwt.Claims) string
		wantHint     string // fosite's hint for the non-time problem; empty skips the check
	}{
		{
			name:     "bad signature and expired",
			wantHint: "Unable to verify the integrity",
			claims:   expired,
			sign: func(t *testing.T, _ *assertionHarness, claims jwt.Claims) string {
				t.Helper()
				other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return signAssertion(t, other, assertionTestKeyID, claims)
			},
		},
		{
			name:   "unknown kid and issued in the future",
			claims: func(h *assertionHarness) func(*jwt.Claims) { return h.skewIAT },
			sign: func(t *testing.T, h *assertionHarness, claims jwt.Claims) string {
				t.Helper()
				return signAssertion(t, h.key, "no-such-key", claims)
			},
		},
		{
			name: "client_secret client and issued in the future",
			mutateClient: func(c *fosite.DefaultOpenIDConnectClient) {
				c.TokenEndpointAuthMethod = "client_secret_basic"
			},
			claims:   func(h *assertionHarness) func(*jwt.Claims) { return h.skewIAT },
			wantHint: "only supports client authentication method 'client_secret_basic'",
		},
		{
			name: "wrong signing algorithm and expired",
			mutateClient: func(c *fosite.DefaultOpenIDConnectClient) {
				c.TokenEndpointAuthSigningAlgorithm = "RS256"
			},
			claims:   expired,
			wantHint: "enforces signing algorithm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newAssertionHarness(t, tt.mutateClient)
			claims := h.claims("jti-order")
			tt.claims(h)(&claims)
			assertion := signAssertion(t, h.key, assertionTestKeyID, claims)
			if tt.sign != nil {
				assertion = tt.sign(t, h, claims)
			}

			_, err := h.authenticateAssertion(t, assertion, nil)
			require.Error(t, err)
			rfcErr := requireInvalidClient(t, err)
			if tt.wantHint != "" {
				assert.Contains(t, rfcErr.HintField, tt.wantHint)
			}
			assert.Zero(t, h.store.validCalls, "the jti must not be checked for an unverified assertion")
			assert.Empty(t, h.store.seen)
		})
	}
}

// TestNewAuthorizationServer_ClientAssertionClockSkew pins that the provider
// installs the clock skew strategy inside the error mapping.
func TestNewAuthorizationServer_ClientAssertionClockSkew(t *testing.T) {
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

	authenticate := func(t *testing.T, h *assertionHarness, config *AuthorizationServerConfig) error {
		t.Helper()
		provider, err := NewAuthorizationServer(config, h.store, nil)
		require.NoError(t, err)
		fositeProvider, ok := provider.(*fosite.Fosite)
		require.True(t, ok)

		claims := h.claims("jti-provider")
		claims.IssuedAt = jwt.NewNumericDate(time.Now().Add(30 * time.Second))
		claims.Expiry = jwt.NewNumericDate(time.Now().Add(time.Minute))
		form := url.Values{
			"client_assertion_type": {privateKeyJWTAssertionType},
			"client_assertion":      {signAssertion(t, h.key, assertionTestKeyID, claims)},
		}
		req := httptest.NewRequest(http.MethodPost, assertionTestTokenURL, strings.NewReader(form.Encode()))
		_, err = fositeProvider.AuthenticateClient(context.Background(), req, form)
		return err
	}

	t.Run("an assertion issued 30s ahead authenticates", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, authenticate(t, newAssertionHarness(t, nil), config))
	})

	t.Run("a recorded jti store failure is a server error", func(t *testing.T) {
		t.Parallel()
		h := newAssertionHarness(t, nil)
		h.store.validErr = errors.New("redis: connection refused")
		h.store.recordValidErr = true

		var rfcErr *fosite.RFC6749Error
		require.ErrorAs(t, authenticate(t, h, config), &rfcErr)
		assert.Equal(t, fosite.ErrServerError.ErrorField, rfcErr.ErrorField)
	})

	t.Run("a caller-supplied strategy gets no recovery", func(t *testing.T) {
		t.Parallel()
		custom := *config
		customFosite := *config.Config
		customFosite.ClientAuthenticationStrategy = func(context.Context, *http.Request, url.Values) (fosite.Client, error) {
			return nil, errors.New("Token is expired")
		}
		custom.Config = &customFosite
		h := newAssertionHarness(t, nil)

		err := authenticate(t, h, &custom)

		requireInvalidClient(t, err)
		assert.Zero(t, h.store.getClientCalls)
		assert.Zero(t, h.store.validCalls)
		assert.Empty(t, h.store.seen)
	})
}
