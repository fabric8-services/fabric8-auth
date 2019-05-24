package service

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/fabric8-services/fabric8-auth/adminconsole/client"
	service "github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/goasupport"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"

	goaclient "github.com/goadesign/goa/client"
)

// NewService creates a new service.
func NewService(context servicecontext.ServiceContext, config Configuration) service.AdminConsoleService {
	return &adminConsoleServiceImpl{
		BaseService: base.NewBaseService(context),
		config:      config,
	}
}

// Configuration the service configuration
type Configuration interface {
	manager.TokenManagerConfiguration
	GetAdminConsoleServiceURL() string
}

type adminConsoleServiceImpl struct {
	base.BaseService
	config Configuration
}

var _ service.AdminConsoleService = &adminConsoleServiceImpl{}

// CreateAuditLog creates an audit log of the given type for the given username on the remote admin console service.
func (s *adminConsoleServiceImpl) CreateAuditLog(ctx context.Context, username string, eventType string) error {
	c, err := s.createSignedClient()
	if err != nil {
		return err
	}
	resp, err := c.CreateAuditLog(goasupport.ForwardContextRequestID(ctx), client.CreateAuditLogPath(username),
		&client.CreateAuditLogPayload{
			Data: &client.CreateAuditLogData{
				Type: "audit_logs",
				Attributes: &client.CreateAuditLogDataAttributes{
					EventType: eventType,
				},
			},
		})
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"username":   username,
			"event_type": eventType,
		}, "unable to create auditlog on admin console service")
		return err
	}
	defer rest.CloseResponse(resp)
	if resp.StatusCode >= 400 {
		body := rest.ReadBody(resp.Body)
		err := errors.NewInternalErrorFromString(fmt.Sprintf("failed to create audit log in admin console service: %s; response body: %s", resp.Status, body))
		log.Error(ctx, map[string]interface{}{
			"status":     resp.StatusCode,
			"username":   username,
			"event_type": eventType,
			"err":        err,
		}, "unexpected response code")
		return err
	}
	return nil

}

// CreateSignedClient creates a client with a JWT signer which uses the Auth Service Account token
func (s *adminConsoleServiceImpl) createSignedClient() (*client.Client, error) {
	cln, err := s.createClient()
	if err != nil {
		return nil, err
	}
	m, err := manager.DefaultManager(s.config)
	if err != nil {
		return nil, err
	}
	signer := m.AuthServiceAccountSigner()
	cln.SetJWTSigner(signer)
	return cln, nil
}

func (s *adminConsoleServiceImpl) createClient() (*client.Client, error) {
	u, err := url.Parse(s.config.GetAdminConsoleServiceURL())
	if err != nil {
		return nil, err
	}
	c := client.New(goaclient.HTTPClientDoer(http.DefaultClient))
	c.Host = u.Host
	c.Scheme = u.Scheme
	return c, nil
}
