package worker

import (
	"context"
	"time"

	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/log"

	"cirello.io/pglock"
)

// Worker the base worker
type Worker struct {
	Ctx    context.Context
	App    application.Application
	Name   string // name of the lock (eg: "user_deactivation_notification"), to use when claiming a lock
	Owner  string // owner of the lock (eg, the name of the Pod), to use when claiming a lock
	Do     func() // the function to run the business code at each cycle of the worker
	lock   *pglock.Lock
	ticker *time.Ticker
	stopCh chan bool
}

// Start starts the worker with the given timer
func (w *Worker) Start(freq time.Duration) {
	w.stopCh = make(chan bool, 1)
	log.Info(w.Ctx, map[string]interface{}{
		"owner": w.Owner,
		"name":  w.Name,
	}, "starting worker")

	w.ticker = time.NewTicker(freq)
	go func() {
		for {
			select {
			case <-w.ticker.C:
				w.execute()
			case <-w.stopCh:
				w.cleanup()
				return
			}
		}
	}()
}

func (w *Worker) execute() {
	if w.Do == nil {
		log.Warn(w.Ctx, map[string]interface{}{
			"name": w.Name,
		}, "nothing to do in this worker?!?")
		return
	}
	l, err := w.App.WorkerLockRepository().AcquireLock(w.Ctx, w.Owner, w.Name)
	if err != nil {
		log.Warn(w.Ctx, map[string]interface{}{
			"error": err,
			"owner": w.Owner,
			"name":  w.Name,
		}, "unable to acquire lock (which is OK if another pod has already acquired it)")
		return
	}
	defer func() {
		if w.lock != nil {
			err := w.lock.Close()
			if err != nil {
				log.Error(w.Ctx, map[string]interface{}{
					"err":   err,
					"owner": w.Owner,
					"name":  w.Name,
				}, "error while releasing worker lock")
			} else {
				log.Info(w.Ctx, map[string]interface{}{
					"owner": w.Owner,
					"name":  w.Name,
				}, "released worker lock")
			}
		}
	}()
	w.lock = l
	w.Do()
}

// Stop stops the worker
func (w *Worker) Stop() {
	if w.stopCh != nil {
		log.Debug(w.Ctx, map[string]interface{}{
			"name":  w.Name,
			"owner": w.Owner,
		}, "time to stop the worker")
		w.stopCh <- true
	}
}

func (w *Worker) cleanup() {
	log.Warn(w.Ctx, map[string]interface{}{
		"owner": w.Owner,
		"name":  w.Name,
	}, "stopping the worker")
	w.ticker.Stop()

}
