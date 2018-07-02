// Package token_context contains the code that extract token manager from the
// context.
package tokencontext

import (
	"context"
)

type contextTMKey int

const (
	_ = iota
	//contextTokenManagerKey is a key that will be used to put and to get `tokenManager` from goa.context
	contextTokenManagerKey contextTMKey = iota
)

// ReadTokenManagerFromContext returns an interface that encapsulates the
// tokenManager extracted from context. This interface can be safely converted.
// Must have been set by ContextWithTokenManager ONLY.
func ReadTokenManagerFromContext(ctx context.Context) interface{} {
	return ctx.Value(contextTokenManagerKey)
}

// ContextWithTokenManager injects tokenManager in the context for every incoming request
// Accepts Token.Manager in order to make sure that correct object is set in the context.
// Only other possible value is nil
func ContextWithTokenManager(ctx context.Context, tm interface{}) context.Context {
	return context.WithValue(ctx, contextTokenManagerKey, tm)
}
