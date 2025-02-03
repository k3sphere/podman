//go:build amd64 || arm64

package k3s

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/containers/podman/v5/cmd/podman/registry"
	"github.com/containers/podman/v5/cmd/podman/utils"
	define "github.com/containers/podman/v5/pkg/k3s/define"
	"github.com/containers/podman/v5/pkg/machine"
	define2 "github.com/containers/podman/v5/pkg/machine/define"
	"github.com/containers/podman/v5/pkg/machine/env"
	"github.com/containers/podman/v5/pkg/machine/vmconfigs"
	"github.com/spf13/cobra"
)

var (
	initCmd = &cobra.Command{
		Use:               "init [options] [NAME] [COMMAND [ARG ...]]",
		Short:             "init k3s cluster",
		Long:              "init k3s cluster",
		PersistentPreRunE: machinePreRunE,
		RunE:              ssh,
		Example: `podman k3s int podman-machine-default
  podman k3s init`,
		ValidArgsFunction: autocompleteMachineSSH,
	}
)

var (
	initOpts           define.InitOptions
	defaultMachineName = define.DefaultMachineName
)

func init() {
	initCmd.Flags().SetInterspersed(false)
	registry.Commands = append(registry.Commands, registry.CliCommand{
		Command: initCmd,
		Parent:  k3sCmd,
	})

}

// TODO Remember that this changed upstream and needs to updated as such!

func ssh(cmd *cobra.Command, args []string) error {
	var (
		err     error
		mc      *vmconfigs.MachineConfig
		validVM bool
	)

	dirs, err := env.GetMachineDirs(provider.VMType())
	if err != nil {
		return err
	}

	// Set the VM to default
	vmName := defaultMachineName
	// If len is greater than 0, it means we may have been
	// provided the VM name.  If so, we check.  The VM name,
	// if provided, must be in args[0].
	if len(args) > 0 {
		// note: previous incantations of this up by a specific name
		// and errors were ignored.  this error is not ignored because
		// it implies podman cannot read its machine files, which is bad
		machines, err := vmconfigs.LoadMachinesInDir(dirs)
		if err != nil {
			return err
		}

		mc, validVM = machines[args[0]]
		if validVM {
			vmName = args[0]
		} else {
			//initOpts.Args = append(initOpts.Args, args[0])
		}
	}

	// If the machine config was not loaded earlier, we load it now
	if mc == nil {
		mc, err = vmconfigs.LoadMachineByName(vmName, dirs)
		if err != nil {
			return fmt.Errorf("vm %s not found: %w", vmName, err)
		}
	}

	if !validVM && initOpts.Username == "" {
		initOpts.Username, err = remoteConnectionUsername()
		if err != nil {
			return err
		}
	}

	state, err := provider.State(mc, false)
	if err != nil {
		return err
	}
	if state != define2.Running {
		return fmt.Errorf("vm %q is not running", mc.Name)
	}

	username := initOpts.Username
	if username == "" {
		username = mc.SSH.RemoteUsername
	}

	// Get a list of all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Error getting interfaces:", err)
		os.Exit(1)
	}

	var ipAddresses []string

	// Loop through the interfaces to collect IP addresses
	for _, iface := range interfaces {
		// Skip interfaces that are down or are loopback
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Get all addresses for the interface
		addrs, err := iface.Addrs()
		if err != nil {
			fmt.Printf("Error getting addresses for interface %s: %v\n", iface.Name, err)
			continue
		}

		for _, addr := range addrs {
			// Parse the IP address
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// Skip IPv6 and loopback addresses
			if ip == nil || ip.IsLoopback() || ip.To4() == nil {
				continue
			}

			// Add the IP address to the list
			ipAddresses = append(ipAddresses, ip.String())
		}
	}

	// Format the IP addresses for the --tls-san option
	if len(ipAddresses) == 0 {
		fmt.Println("No IP addresses found.")
		os.Exit(1)
	}
	tlsSanArgs := "--tls-san " + strings.Join(ipAddresses, " --tls-san ")

	// Construct the INSTALL_K3S_EXEC environment variable
	installCommand := fmt.Sprintf("curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC=\"%s\" sh -", tlsSanArgs)

	// Output the installation command
	fmt.Println("Run the following command to install K3s with all local IPs:")
	fmt.Println(installCommand)

	initOpts.Args = []string{installCommand}
	err = machine.CommonSSHShell(username, mc.SSH.IdentityPath, mc.Name, mc.SSH.Port, initOpts.Args)
	return utils.HandleOSExecError(err)
}

func remoteConnectionUsername() (string, error) {
	con, err := registry.PodmanConfig().ContainersConfDefaultsRO.GetConnection("", true)
	if err != nil {
		return "", err
	}

	uri, err := url.Parse(con.URI)
	if err != nil {
		return "", err
	}
	username := uri.User.String()
	return username, nil
}
