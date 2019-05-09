package worker

import (
	"context"
	"time"

	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/log"
	worker "github.com/fabric8-services/fabric8-auth/worker"
)

const (
	// UserDeactivationNotification the name of the worker that notifies users to deactivate.
	// Also, the name of the lock used by this worker.
	UserDeactivationNotification = "user-deactivation-notification"
)

// NewUserDeactivationNotificationWorker returns a new UserDeactivationNotificationWorker
func NewUserDeactivationNotificationWorker(ctx context.Context, app application.Application) worker.Worker {
	w := &userDeactivationNotificationWorker{
		worker.BaseWorker{
			Ctx:   ctx,
			App:   app,
			Owner: worker.GetLockOwner(ctx),
			Name:  UserDeactivationNotification,
		},
	}
	w.Do = w.notifyUsers
	return w
}

type userDeactivationNotificationWorker struct {
	worker.BaseWorker
}

func (w *userDeactivationNotificationWorker) notifyUsers() {
	log.Info(w.Ctx, map[string]interface{}{
		"owner": w.Owner,
	}, "starting cycle of inactive users notifications")
	identities, err := w.App.UserService().NotifyIdentitiesBeforeDeactivation(w.Ctx, time.Now) // user service has the config settings to limit the number of users to notify
	if err != nil {
		// We will just log the error and continue
		log.Error(nil, map[string]interface{}{
			"err": err,
		}, "error while notifying users to deactivate")
	}
	log.Info(w.Ctx, map[string]interface{}{
		"identities": len(identities),
		"owner":      w.Owner,
	}, "ending cycle of inactive users notifications")
}
