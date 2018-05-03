package service

import (
	"context"
	"net/http"
	"net/url"

	"github.com/fabric8-services/fabric8-auth/account/tenant"
	"github.com/fabric8-services/fabric8-auth/goasupport"
	"github.com/fabric8-services/fabric8-auth/rest"

	"github.com/goadesign/goa/client"
)

type tenantConfig interface {
	GetTenantServiceURL() string
}

type Tenant interface {
	Init(ctx context.Context) error
}

type tenantImpl struct {
	config tenantConfig
}

// NewTenant creates a new tenant service
func NewTenant(config tenantConfig) Tenant {
	return &tenantImpl{config: config}
}

// Init creates a new tenant in OSO
func (t *tenantImpl) Init(ctx context.Context) error {
	c, err := createClient(ctx, t.config)
	if err != nil {
		return err
	}

	// Ignore response for now
	response, err := c.SetupTenant(goasupport.ForwardContextRequestID(ctx), tenant.SetupTenantPath())
	if err == nil {
		defer rest.CloseResponse(response)
	}

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
