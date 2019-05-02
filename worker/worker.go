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
	Ctx   context.Context
	App   application.Application
	Name  string // name of the lock (eg: "user_deactivation_notification"), to use when claiming a lock
	Owner string // owner of the lock (eg, the name of the Pod), to use when claiming a lock
	Do    func() // the function to run the business code at each cycle of the worker
	Opts  []pglock.ClientOption

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
		w.acquireLock() // will wait until succeed
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

func (w *Worker) acquireLock() {
	l, err := w.App.WorkerLockRepository().AcquireLock(w.Ctx, w.Owner, w.Name, w.Opts...)
	if err != nil {
		log.Warn(w.Ctx, map[string]interface{}{
			"error": err,
			"owner": w.Owner,
			"name":  w.Name,
		}, "unable to acquire lock (which is OK if another pod has already acquired it)")
		return
	}
	// worker tries to acquire the lock at each cycle, so when the lock is released
	// by the owner pod (during shutdown), then another pod can take the work.
	log.Info(w.Ctx, map[string]interface{}{
		"owner": w.Owner,
		"name":  w.Name,
	}, "acquired lock")
	w.lock = l
}

func (w *Worker) execute() {
	// Check if the lock is still hold by the current owner
	l, err := w.App.WorkerLockRepository().GetLock(w.Ctx, w.Name)
	if err != nil {
		log.Warn(w.Ctx, map[string]interface{}{
			"error": err,
			"owner": w.Owner,
			"name":  w.Name,
		}, "unable to check the existing lock's owner")
		return
	}
	if l.Owner() != w.Owner {
		// Theoretically it can happen if the heartbeat failed for some reason and the lock has been acquired by another owner
		log.Error(w.Ctx, map[string]interface{}{
			"owner": w.Owner,
			"name":  w.Name,
		}, "the current owner lost the lock! will try to re-acquire it")
		w.acquireLock() // will wait until succeed
	}
	if w.Do == nil {
		log.Warn(w.Ctx, map[string]interface{}{
			"name": w.Name,
		}, "nothing to do in this worker?!?")
		return
	}
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
	// stop the ticker
	log.Warn(w.Ctx, map[string]interface{}{
		"owner": w.Owner,
		"name":  w.Name,
	}, "stopping the worker")
	w.ticker.Stop()
	// release the global lock
	log.Warn(w.Ctx, map[string]interface{}{
		"owner": w.Owner,
		"name":  w.Name,
	}, "releasing the worker lock")
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
			}, "worker lock released")
		}
	}

}
