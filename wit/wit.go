package wit

type Configuration interface {
	GetWITURL() (string, error)
}
