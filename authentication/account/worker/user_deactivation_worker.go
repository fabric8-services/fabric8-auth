package worker

import (
	"context"
	"time"

	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/worker"
)

// UserDeactivationWorker the interface for the User Deactivation Worker,
// which takes care of deactivating accounts of inactive users who were previously notified but did not come back afterwards.
type UserDeactivationWorker interface {
	Start(freq time.Duration)
	Stop()
}

const (
	// UserDeactivation the name of the worker that deactivates users.
	// Also, the name of the lock used by this worker.
	UserDeactivation = "user-deactivation"
)

// NewUserDeactivationWorker returns a new UserDeactivationWorker
func NewUserDeactivationWorker(ctx context.Context, app application.Application) UserDeactivationWorker {
	w := &userDeactivationWorker{
		worker.Worker{
			Ctx:   ctx,
			App:   app,
			Owner: worker.GetLockOwner(ctx),
			Name:  "user-deactivation",
		},
	}
	w.Do = w.deactivateUsers
	return w
}

type userDeactivationWorker struct {
	worker.Worker
}

func (w *userDeactivationWorker) deactivateUsers() {
	log.Debug(w.Ctx, map[string]interface{}{
		"owner": w.Owner,
	}, "starting cycle of inactive users deactivation")
	// user service has the config settings to limit the number of users to deactivate
	identities, err := w.App.UserService().ListIdentitiesToDeactivate(w.Ctx, time.Now)
	if err != nil {
		// We will just log the error and continue
		log.Error(nil, map[string]interface{}{
			"err": err,
		}, "error while notifying users to deactivate")
		return
	}
	for _, identity := range identities {
		// to deactivate a user, we need to call the OSO Registration App which will take care of
		// deactivating the user on OSO and then call back `auth` service (on its `/namedusers/:username/deactivate` endpoint)
		// which will handle the deactivation on the OSIO platform
		err := w.App.OSOSubscriptionService().DeactivateUser(w.Ctx, identity.Username)
		if err != nil {
			// We will just log the error and continue
			log.Error(nil, map[string]interface{}{
				"err":      err,
				"username": identity.Username,
			}, "error while deactivating user")
		} else {
			log.Info(nil, map[string]interface{}{
				"username": identity.Username,
			}, "user account deactivation triggered")
		}
	}
	log.Debug(w.Ctx, map[string]interface{}{
		"identities": len(identities),
		"owner":      w.Owner,
	}, "ending cycle of inactive users deactivation")
}
