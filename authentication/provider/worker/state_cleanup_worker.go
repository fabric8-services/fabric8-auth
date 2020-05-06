package worker

import (
	"context"

	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/worker"
)

const (
	// OAuthStateReferenceCleanup the name of the worker that cleans up old OAuth state references.
	// Also, the name of the lock used by this worker.
	OAuthStateReferenceCleanup = "oauth-state-reference-cleanup"
)

// NewOAuthStateReferenceCleanupWorker returns a new OAuthStateReferenceCleanupWorker
func NewOAuthStateReferenceCleanupWorker(ctx context.Context, app application.Application) worker.Worker {
	w := &oauthStateReferenceCleanupWorker{
		worker.BaseWorker{
			Ctx:   ctx,
			App:   app,
			Owner: worker.GetLockOwner(ctx),
			Name:  OAuthStateReferenceCleanup,
		},
	}
	w.Do = w.cleanup
	return w
}

type oauthStateReferenceCleanupWorker struct {
	worker.BaseWorker
}

func (w oauthStateReferenceCleanupWorker) cleanup() {
	log.Info(w.Ctx, map[string]interface{}{
		"owner": w.Owner,
	}, "starting cycle of cleaning up old OAuth state references")
	// user service has the config settings to limit the number of users to deactivate
	if err := w.App.OauthStates().Cleanup(w.Ctx); err != nil {
		// We will just log the error and continue
		log.Error(nil, map[string]interface{}{
			"err": err,
		}, "error while cleaning up old OAuth state references")
	}
	log.Info(w.Ctx, map[string]interface{}{}, "ending cycle of OAuth state references cleanup")
}
