package account

import (
	"context"
	"net/http"
	"net/url"

	"github.com/fabric8-services/fabric8-auth/account/tenant"
	"github.com/fabric8-services/fabric8-auth/goasupport"
	"github.com/goadesign/goa/client"
)

type tenantConfig interface {
	GetTenantServiceURL() string
}

// NewInitTenant creates a new tenant service in oso
func NewInitTenant(config tenantConfig) func(context.Context) error {
	return func(ctx context.Context) error {
		return InitTenant(ctx, config)
	}
}

// InitTenant creates a new tenant service in oso
func InitTenant(ctx context.Context, config tenantConfig) error {
	c, err := createClient(ctx, config)
	if err != nil {
		return err
	}

	// Ignore response for now
	_, err = c.SetupTenant(goasupport.ForwardContextRequestID(ctx), tenant.SetupTenantPath())

	return err
}

func createClient(ctx context.Context, config tenantConfig) (*tenant.Client, error) {
	u, err := url.Parse(config.GetTenantServiceURL())
	if err != nil {
		return nil, err
	}

	c := tenant.New(client.HTTPClientDoer(http.DefaultClient))
	c.Host = u.Host
	c.Scheme = u.Scheme
	c.SetJWTSigner(goasupport.NewForwardSigner(ctx))
	return c, nil
}
