package configuration

import (
	"sync"

	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/fsnotify/fsnotify"
)

var mux sync.Mutex

func ClusterWatcher(config *ConfigurationData) (func() error, error) {
	return watcher(config, defaultOsoClusterConfigPath)
}

func watcher(config *ConfigurationData, clusterConfigFile string) (func() error, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			select {
			case event := <-watcher.Events:
				if event.Op&fsnotify.Write == fsnotify.Write {
					reloadConfig(config, clusterConfigFile)
					log.Debug(nil, map[string]interface{}{
						"file": event.Name,
					}, "cluster config file modified and reloaded")
				}
			case err := <-watcher.Errors:
				log.Error(nil, map[string]interface{}{
					"err": err,
				}, "cluster config file watcher error")
			}
		}
	}()

	configFilePath, err := pathExists(clusterConfigFile)
	if err == nil && configFilePath != "" {
		err = watcher.Add(configFilePath)
	} else {
		// OK in Dev Mode
		log.Warn(nil, map[string]interface{}{
			"file": clusterConfigFile,
		}, "cluster config file watcher not initialized for non-existent file")
	}

	return watcher.Close, err
}

func reloadConfig(config *ConfigurationData, clusterConfigFile string) {
	mux.Lock()
	defer mux.Unlock()
	config.initClusterConfig("", clusterConfigFile)
}
