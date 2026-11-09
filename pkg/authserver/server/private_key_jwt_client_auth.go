// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"log/slog"
	"math"
	"net/http"
	"net/url"

	jwtv3 "github.com/go-jose/go-jose/v3/jwt"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/ory/fosite"
)

// clientAssertionAudienceConfig overrides the token URLs fosite accepts as the
// audience of a client assertion. fosite reads them only when authenticating
// clients; every other Configurator method comes from the embedded config.
type clientAssertionAudienceConfig struct {
	*fosite.Config
	tokenURLs []string
}

func (c clientAssertionAudienceConfig) GetTokenURLs(context.Context) []string {
	return c.tokenURLs
}

// newClientAssertionAudienceConfig wraps config so that client assertions may
// carry either the issuer or the token endpoint URL as audience.
func newClientAssertionAudienceConfig(config *fosite.Config) clientAssertionAudienceConfig {
	return clientAssertionAudienceConfig{
		Config:    config,
		tokenURLs: []string{config.AccessTokenIssuer, config.TokenURL},
	}
}

// newClientAssertionExpiryStrategy refuses a private_key_jwt client assertion
// that fosite accepted but whose exp is missing or not positive. fosite treats
// an exp of 0 as absent, and a replay marker kept until exp then has a deadline
// in 1970, so the assertion could be presented again and again. An exp that
// does not fit the range the claims parser reads is refused too, because the
// replay marker deadline cannot be computed for it.
//
// It must sit inside newClientAssertionErrorStrategy so that the refusal is
// returned like every other client assertion verdict.
func newClientAssertionExpiryStrategy(next fosite.ClientAuthenticationStrategy) fosite.ClientAuthenticationStrategy {
	return func(ctx context.Context, r *http.Request, form url.Values) (fosite.Client, error) {
		client, err := next(ctx, r, form)
		if err != nil || !isPrivateKeyJWTRequest(form) {
			return client, err
		}
		// fosite verified these bytes, so reading the claims without verifying
		// them again is safe.
		claims, ok := readAcceptedClientAssertionTimeClaims(form.Get("client_assertion"))
		if !ok {
			slog.Debug("client assertion refused: claims unreadable", "client_id", client.GetID())
			return nil, fosite.ErrInvalidClient.WithHint("The 'client_assertion' claims could not be read.")
		}
		if claims.Expiry == nil || claims.Expiry.Time().Unix() <= 0 {
			slog.Debug("client assertion refused: exp missing or not positive", "client_id", client.GetID())
			return nil, fosite.ErrInvalidClient.WithHint("The 'client_assertion' must have a positive 'exp'.")
		}
		return client, nil
	}
}

// readAcceptedClientAssertionTimeClaims reads exp, iat and nbf of an assertion
// that fosite has already verified and accepted, without verifying it again.
// It reads the assertion the way fosite does, with go-jose v3 into an untyped
// map: whitespace in the compact form is ignored, and an iat or nbf that is not
// a number counts as absent. A stricter reader would refuse assertions that
// fosite accepts. exp is reported absent, and ok is false, when it is not a
// number that fits an int64, because the replay marker deadline cannot be
// computed for it. Claims other than the three time claims are left unset.
func readAcceptedClientAssertionTimeClaims(assertion string) (claims jwt.Claims, ok bool) {
	parsed, err := jwtv3.ParseSigned(assertion)
	if err != nil {
		return jwt.Claims{}, false
	}
	var raw map[string]any
	if err := parsed.UnsafeClaimsWithoutVerification(&raw); err != nil {
		return jwt.Claims{}, false
	}
	if exp, present := claimAsSeconds(raw["exp"]); present {
		claims.Expiry = &exp
	} else if raw["exp"] != nil {
		return jwt.Claims{}, false
	}
	if iat, present := claimAsSeconds(raw["iat"]); present {
		claims.IssuedAt = &iat
	}
	if nbf, present := claimAsSeconds(raw["nbf"]); present {
		claims.NotBefore = &nbf
	}
	return claims, true
}

// claimAsSeconds converts a decoded JSON number claim to a NumericDate. It
// reports false for a value that is not a number or does not fit an int64.
func claimAsSeconds(v any) (jwt.NumericDate, bool) {
	f, isNumber := v.(float64)
	if !isNumber || f >= math.MaxInt64 || f <= math.MinInt64 {
		return 0, false
	}
	return jwt.NumericDate(int64(f)), true
}
