package cluster

// Cluster represents an OpenShift cluster configuration
type Cluster struct {
	Name                   string `mapstructure:"name"`
	APIURL                 string `mapstructure:"api-url"`
	ConsoleURL             string `mapstructure:"console-url"` // Optional in oso-clusters.conf
	MetricsURL             string `mapstructure:"metrics-url"` // Optional in oso-clusters.conf
	LoggingURL             string `mapstructure:"logging-url"` // Optional in oso-clusters.conf
	AppDNS                 string `mapstructure:"app-dns"`
	ServiceAccountToken    string `mapstructure:"service-account-token"`
	ServiceAccountUsername string `mapstructure:"service-account-username"`
	TokenProviderID        string `mapstructure:"token-provider-id"`
	AuthClientID           string `mapstructure:"auth-client-id"`
	AuthClientSecret       string `mapstructure:"auth-client-secret"`
	AuthClientDefaultScope string `mapstructure:"auth-client-default-scope"`
	CapacityExhausted      bool   `mapstructure:"capacity-exhausted"` // Optional in oso-clusters.conf ('false' by default)
	Type                   string `mapstructure:"type"`               // Optional in oso-clusters.conf
}
