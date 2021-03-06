package worker

import (
	"context"
	"time"

	"github.com/fabric8-services/fabric8-auth/application"
	autherrors "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/metric"
	"github.com/fabric8-services/fabric8-auth/worker"
)

const (
	// UserDeactivation the name of the worker that deactivates users.
	// Also, the name of the lock used by this worker.
	UserDeactivation = "user-deactivation"
)

// NewUserDeactivationWorker returns a new UserDeactivationWorker
func NewUserDeactivationWorker(ctx context.Context, app application.Application) worker.Worker {
	w := &userDeactivationWorker{
		worker.BaseWorker{
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
	worker.BaseWorker
}

func (w userDeactivationWorker) deactivateUsers() {
	log.Info(w.Ctx, map[string]interface{}{
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
		err := w.App.UserService().RescheduleDeactivation(w.Ctx, identity.ID)
		if err != nil {
			log.Error(nil, map[string]interface{}{
				"err":      err,
				"username": identity.Username,
			}, "error updating deactivation schedule while deactivating user")
		}
		// to deactivate a user, we need to call the OSO Registration App which will take care of
		// deactivating the user on OSO and then call back `auth` service (on its `/namedusers/:username/deactivate` endpoint)
		// which will handle the deactivation on the OSIO platform
		err = w.App.OSOSubscriptionService().DeactivateUser(w.Ctx, identity.Username)
		if err != nil {
			if _, ok := err.(autherrors.NotFoundError); ok {
				// deactivate user directly
				_, err := w.App.UserService().DeactivateUser(w.Ctx, identity.Username)
				if err != nil {
					log.Error(nil, map[string]interface{}{
						"err":      err,
						"username": identity.Username,
					}, "error during deactivating user")
				} else {
					log.Info(nil, map[string]interface{}{
						"username": identity.Username,
					}, "user deactivation is successful")
				}
			} else {
				// We will just log the error and continue
				metric.RecordUserDeactivationTrigger(false)
				log.Error(nil, map[string]interface{}{
					"err":      err,
					"username": identity.Username,
				}, "error while triggering user deactivation")
			}
		} else {
			metric.RecordUserDeactivationTrigger(true)
			log.Info(nil, map[string]interface{}{
				"username": identity.Username,
			}, "user account deactivation triggered")
		}
	}
	log.Info(w.Ctx, map[string]interface{}{
		"identities": len(identities),
		"owner":      w.Owner,
	}, "ending cycle of inactive users deactivation")
}
