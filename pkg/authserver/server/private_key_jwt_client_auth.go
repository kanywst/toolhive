// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	jwtv3 "github.com/go-jose/go-jose/v3/jwt"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/ory/fosite"

	servercrypto "github.com/stacklok/toolhive/pkg/authserver/server/crypto"
)

// clientAssertionSigningAlgorithms are the algorithms a private_key_jwt
// client may register, which are the ones fosite verifies.
var clientAssertionSigningAlgorithms = func() []jose.SignatureAlgorithm {
	supported := servercrypto.SupportedClientKeyAlgorithms()
	algs := make([]jose.SignatureAlgorithm, len(supported))
	for i, alg := range supported {
		algs[i] = jose.SignatureAlgorithm(alg)
	}
	return algs
}()

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
		tokenURLs: clientAssertionAudiences(config),
	}
}

// clientAssertionAudiences returns the values accepted as the audience of a
// client assertion: the issuer and the token endpoint URL.
func clientAssertionAudiences(config *fosite.Config) []string {
	return []string{config.AccessTokenIssuer, config.TokenURL}
}

// clientAssertionStore is the part of fosite.Storage that the clock skew
// fallback uses to finish what fosite's strategy would have done.
type clientAssertionStore interface {
	GetClient(ctx context.Context, id string) (fosite.Client, error)
	ClientAssertionJWTValid(ctx context.Context, jti string) error
	SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error
}

// newClientAssertionClockSkewStrategy lets a private_key_jwt client assertion
// whose exp, iat or nbf is within clientAssertionClockSkew of now authenticate,
// and refuses one with a lifetime above MaxAssertionLifespan or without a
// positive exp. fosite offers no leeway setting, and its jwt.TimeFunc is a
// process-wide variable, so fosite stays the validator and this wrapper only
// recovers from its time errors. audiences are the values accepted in aud.
//
// recoverTimeErrors turns the recovery on. Only fosite's own strategy may have
// it, because the recovery relies on fosite verifying the signature before it
// validates the claims. A caller-supplied strategy has no such guarantee, so
// with recoverTimeErrors false its time errors are returned unchanged, and only
// the exp and lifetime check on success applies. That check reads the claims of
// an accepted assertion, so it must be signed with an algorithm fosite verifies.
//
// It must sit inside newClientAssertionErrorStrategy, so that a storage failure
// recorded during the fallback's own jti check still surfaces as server_error.
//
// Deliberate deviations: the skew also applies to exp, which RFC 7523 section 3
// item 4 allows. The token exchange assertion checks stay strict because their
// exp bounds a token this server issues. A missing iat is treated as now,
// because iat is optional (RFC 7523 section 3, OIDC Core section 9).
func newClientAssertionClockSkewStrategy(
	next fosite.ClientAuthenticationStrategy,
	store clientAssertionStore,
	audiences []string,
	now func() time.Time,
	recoverTimeErrors bool,
) fosite.ClientAuthenticationStrategy {
	return func(ctx context.Context, r *http.Request, form url.Values) (fosite.Client, error) {
		if !isPrivateKeyJWTRequest(form) {
			return next(ctx, r, form)
		}
		assertion := form.Get("client_assertion")

		client, err := next(ctx, r, form)
		if err == nil {
			// fosite verified these bytes. It treats exp 0 as absent, which would
			// otherwise let a replay marker with a 1970 deadline through.
			claims, ok := readAcceptedClientAssertionTimeClaims(assertion)
			if !ok {
				slog.Debug("client assertion refused: claims unreadable", "client_id", client.GetID())
				return nil, errClientAssertionUnreadable()
			}
			if clientAssertionTimesAcceptable(claims, now()) != assertionTimesOK {
				slog.Debug("client assertion refused: exp or lifetime out of range", "client_id", client.GetID())
				return nil, errClientAssertionLifetime()
			}
			return client, nil
		}

		if !recoverTimeErrors || !isClientAssertionTimeError(err) {
			return client, err
		}
		// fosite verifies the signature before it validates the claims
		// (jwt.ParseWithClaims), and its key lookup has already required the
		// client, its private_key_jwt method, the pinned algorithm and a
		// registered key. A time error therefore means the signature is valid,
		// so the claims can be read without verifying them again. Tests pin
		// this order, because a different order in a later fosite release
		// would make these claims untrusted.
		return recoverSkewedClientAssertion(ctx, store, audiences, form, assertion, now, err)
	}
}

// recoverSkewedClientAssertion repeats the checks fosite stopped before, with
// the clock skew applied. fositeErr is fosite's time error, which describes a
// refusal on a claim outside the skew margin. A SetClientAssertionJWT error is
// returned unchanged. A GetClient error is refused as invalid_client. A storage
// failure while checking the jti is refused as invalid_client here, and becomes
// server_error in newClientAssertionErrorStrategy, which reads the failure the
// backend recorded.
func recoverSkewedClientAssertion(
	ctx context.Context,
	store clientAssertionStore,
	audiences []string,
	form url.Values,
	assertion string,
	now func() time.Time,
	fositeErr error,
) (fosite.Client, error) {
	clientID := form.Get("client_id")
	refuse := func(reason string, err error) (fosite.Client, error) {
		slog.Debug("client assertion refused after clock skew check", "reason", reason, "client_id", clientID)
		return nil, err
	}

	claims, ok := parseVerifiedClientAssertionClaims(assertion)
	if !ok {
		return refuse("claims unreadable", errClientAssertionUnreadable())
	}
	if clientID == "" {
		clientID = claims.Subject
	}
	switch clientAssertionTimesAcceptable(claims, now()) {
	case assertionTimesLifetime:
		return refuse("exp or lifetime out of range", errClientAssertionLifetime())
	case assertionTimesOutsideSkew:
		return refuse("time claims out of range", fositeErr)
	case assertionTimesOK:
	}
	if reason, refusalErr := checkClientAssertionIdentity(claims, clientID, audiences); reason != "" {
		return refuse(reason, refusalErr)
	}

	// Look the client up before reserving the jti, so a failed lookup does not
	// burn it. fosite read the client too, and the record could have changed
	// since, so the auth method is checked again. The key and the algorithm pin
	// are not: fosite verified the signature against them on its own read.
	client, err := store.GetClient(ctx, clientID)
	if err != nil {
		return refuse("client lookup failed", fosite.ErrInvalidClient.WithWrap(err).WithDebug(err.Error()))
	}
	oidcClient, ok := client.(fosite.OpenIDConnectClient)
	if !ok || oidcClient.GetTokenEndpointAuthMethod() != "private_key_jwt" {
		return refuse("client no longer uses private_key_jwt", fosite.ErrInvalidClient.WithHint(
			"The requested OAuth 2.0 Client does not support client authentication method 'private_key_jwt'."))
	}

	if err := store.ClientAssertionJWTValid(ctx, claims.ID); err != nil {
		if errors.Is(err, fosite.ErrJTIKnown) {
			return refuse("jti already used", fosite.ErrInvalidClient.WithHint(
				"Claim 'jti' from 'client_assertion' MUST only be used once."))
		}
		return refuse("jti invalid", fosite.ErrInvalidClient.WithHint(
			"The 'jti' claim of the 'client_assertion' is invalid."))
	}
	// The client lookup and the jti check can take long, so the time claims are
	// judged again with a fresh clock read. The replay marker of a consumed
	// assertion outlives the margin by only clientAssertionReplayGrace. If it
	// expired while this request was waiting, the reservation above succeeded as
	// if the jti were new, but this read is then past the margin and refuses the
	// request. Nothing is recorded for a refused assertion.
	if clientAssertionTimesAcceptable(claims, now()) != assertionTimesOK {
		return refuse("time claims out of range after the jti check", fositeErr)
	}
	if err := store.SetClientAssertionJWT(ctx, claims.ID, claims.Expiry.Time()); err != nil {
		return nil, err
	}
	return client, nil
}

// errClientAssertionLifetime is the refusal for an exp that is not positive or
// a lifetime above MaxAssertionLifespan.
func errClientAssertionLifetime() error {
	return fosite.ErrInvalidClient.WithHintf(
		"The 'client_assertion' must have a positive 'exp' and a lifetime of at most %s.", MaxAssertionLifespan)
}

// errClientAssertionUnreadable is the refusal for claims that cannot be read.
func errClientAssertionUnreadable() error {
	return fosite.ErrInvalidClient.WithHint("The 'client_assertion' claims could not be read.")
}

// checkClientAssertionIdentity checks iss, sub, jti and aud against what fosite
// requires. It returns a refusal reason and error, or an empty reason when the
// claims are fine.
func checkClientAssertionIdentity(claims jwt.Claims, clientID string, audiences []string) (string, error) {
	if clientID == "" || claims.Issuer != clientID {
		return "iss does not match the client", fosite.ErrInvalidClient.WithHint(
			"Claim 'iss' from 'client_assertion' must match the 'client_id' of the OAuth 2.0 Client.")
	}
	if claims.Subject != clientID {
		return "sub does not match the client", fosite.ErrInvalidClient.WithHint(
			"Claim 'sub' from 'client_assertion' must match the 'client_id' of the OAuth 2.0 Client.")
	}
	if claims.ID == "" {
		return "jti missing", fosite.ErrInvalidClient.WithHint(
			"Claim 'jti' from 'client_assertion' must be set but is not.")
	}
	if !slices.ContainsFunc(claims.Audience, func(aud string) bool {
		return aud != "" && slices.Contains(audiences, aud)
	}) {
		return "audience not accepted", fosite.ErrInvalidClient.WithHintf(
			"Claim 'audience' from 'client_assertion' must match the authorization server's token endpoint '%s'.",
			strings.Join(slices.DeleteFunc(slices.Clone(audiences), func(a string) bool { return a == "" }), "' or '"))
	}
	return "", nil
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

// parseVerifiedClientAssertionClaims reads the claims of an assertion without
// verifying the signature. Callers only pass assertions that fosite has
// already verified.
func parseVerifiedClientAssertionClaims(assertion string) (jwt.Claims, bool) {
	var claims jwt.Claims
	parsed, err := jwt.ParseSigned(assertion, clientAssertionSigningAlgorithms)
	if err != nil || parsed.UnsafeClaimsWithoutVerification(&claims) != nil {
		return jwt.Claims{}, false
	}
	return claims, true
}

// assertionTimesVerdict is the result of clientAssertionTimesAcceptable.
type assertionTimesVerdict int

const (
	assertionTimesOK assertionTimesVerdict = iota
	// assertionTimesLifetime means exp is missing or not positive, exp is
	// before iat, or the lifetime is above MaxAssertionLifespan.
	assertionTimesLifetime
	// assertionTimesOutsideSkew means exp, iat or nbf is beyond the margin.
	assertionTimesOutsideSkew
)

// clientAssertionTimesAcceptable applies the exp, iat and nbf margins and the
// lifetime bound. exp must be positive and not before iat. A non-positive iat
// or nbf counts as absent, like in fosite. It compares whole seconds, like
// fosite, and never adds to a claim, so a huge claim cannot overflow. A claim
// outside the margin is reported before the lifetime checks that follow it.
func clientAssertionTimesAcceptable(claims jwt.Claims, now time.Time) assertionTimesVerdict {
	if claims.Expiry == nil {
		return assertionTimesLifetime
	}
	nowSec := now.Unix()
	skewSec := int64(clientAssertionClockSkew / time.Second)
	maxSec := int64(MaxAssertionLifespan / time.Second)

	exp := claims.Expiry.Time().Unix()
	if exp <= 0 {
		return assertionTimesLifetime
	}
	if exp <= nowSec-skewSec {
		return assertionTimesOutsideSkew
	}

	start := nowSec
	if claims.IssuedAt != nil && claims.IssuedAt.Time().Unix() > 0 {
		start = claims.IssuedAt.Time().Unix()
		if start > nowSec+skewSec {
			return assertionTimesOutsideSkew
		}
		if exp < start {
			return assertionTimesLifetime
		}
	}
	if claims.NotBefore != nil && claims.NotBefore.Time().Unix() > nowSec+skewSec {
		return assertionTimesOutsideSkew
	}
	if exp-start > maxSec {
		return assertionTimesLifetime
	}
	return assertionTimesOK
}
