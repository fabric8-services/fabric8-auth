package worker

import (
	"context"
	"time"

	"cirello.io/pglock"

	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/log"
	worker "github.com/fabric8-services/fabric8-auth/worker/repository"
)

// UserDeactivationNotificationWorker the interface for the User Deactivation Worker,
// which takes care of deactivating accounts of inactive users who were previously notified but did not come back afterwards.
type UserDeactivationNotificationWorker interface {
	Start(freq time.Duration)
	Stop()
}

// NewUserDeactivationNotificationWorker returns a new UserDeactivationNotificationWorker
func NewUserDeactivationNotificationWorker(ctx context.Context, app application.Application) UserDeactivationNotificationWorker {
	return &userDeactivationNotificationWorker{
		ctx:   ctx,
		app:   app,
		owner: worker.GetLockOwner(ctx),
	}
}

type userDeactivationNotificationWorker struct {
	ctx    context.Context
	app    application.Application
	lock   *pglock.Lock
	ticker *time.Ticker
	stopCh chan bool
	owner  string
}

// Start starts the worker with the given timer
func (w *userDeactivationNotificationWorker) Start(freq time.Duration) {
	w.stopCh = make(chan bool, 1)
	log.Info(w.ctx, map[string]interface{}{
		"owner": w.owner,
	}, "starting user deactivation notification worker")

	l, err := w.app.WorkerLockRepository().AcquireLockToNotifyUsersToDeactivate(w.ctx)
	if err != nil {
		log.Warn(w.ctx, map[string]interface{}{
			"error": err,
			"owner": w.owner,
		}, "unable to acquire user deactivation notification worker lock which is OK if another pod has already started a worker")
		return
	}
	w.lock = l
	w.ticker = time.NewTicker(freq)
	go func() {
		for {
			select {
			case <-w.ticker.C:
				w.notifyUsers()
			case <-w.stopCh:
				log.Info(w.ctx, map[string]interface{}{
					"owner": w.owner,
				}, "about to stop the user deactivation notification worker...")
				w.stop()
				return
			}
		}
	}()
}

// Stop stops the worker
func (w *userDeactivationNotificationWorker) Stop() {
	if w.stopCh != nil {
		log.Info(w.ctx, map[string]interface{}{
			"owner": w.owner,
		}, "time to stop the user deactivation notification worker")
		w.stopCh <- true
	}
}

func (w *userDeactivationNotificationWorker) stop() {
	log.Info(w.ctx, map[string]interface{}{
		"owner": w.owner,
	}, "stopping user deactivation notification worker")
	w.ticker.Stop()
	if w.lock != nil {
		err := w.lock.Close()
		if err != nil {
			log.Error(w.ctx, map[string]interface{}{
				"err": err,
			}, "error while releasing user deactivation notification worker lock")
		}
		log.Info(w.ctx, map[string]interface{}{
			"owner": w.owner,
		}, "released user deactivation notification worker lock")
	}
}

func (w *userDeactivationNotificationWorker) notifyUsers() {
	log.Debug(w.ctx, map[string]interface{}{
		"owner": w.owner,
	}, "starting cycle of inactive users notifications")
	// get the first user account to deactivate
	identities, err := w.app.UserService().NotifyIdentitiesBeforeDeactivation(w.ctx, time.Now) // user service has the config settings to limit the number of users to notify
	if err != nil {
		// We will just log the error and continue
		log.Error(nil, map[string]interface{}{
			"err": err,
		}, "error while notifying users to deactivate")
	}
	log.Debug(w.ctx, map[string]interface{}{
		"identities": len(identities),
		"owner":      w.owner,
	}, "ending cycle of inactive users notifications")
}
