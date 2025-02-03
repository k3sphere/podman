package k3sdefine

const (
	UserCertsTargetPath = "/etc/containers/certs.d"
	DefaultIdentityName = "machine"
	DefaultMachineName  = "podman-machine-default"
)

type InitOptions struct {
	Username string
	Args     []string
}
