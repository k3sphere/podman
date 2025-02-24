package k3sdefine

const (
	UserCertsTargetPath = "/etc/containers/certs.d"
	DefaultIdentityName = "machine"
	DefaultMachineName  = "podman-machine-default"
)

type InitOptions struct {
	Username string
	Email  string
	Args     []string
	ClientId string
	Issuer   string
	UserClaim string
	GroupsClaim string
	Name string
	OIDC bool
}
