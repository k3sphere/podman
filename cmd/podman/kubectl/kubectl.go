//go:build amd64 || arm64

package kubectl

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/containers/podman/v5/cmd/podman/registry"
	"github.com/containers/podman/v5/cmd/podman/utils"
	"github.com/containers/podman/v5/pkg/machine"
	"github.com/containers/podman/v5/pkg/machine/define"
	"github.com/containers/podman/v5/pkg/machine/env"
	provider2 "github.com/containers/podman/v5/pkg/machine/provider"
	"github.com/containers/podman/v5/pkg/machine/vmconfigs"
	"github.com/spf13/cobra"
)

var (
	// Pull in configured json library
	json = registry.JSONLibrary()

	openEventSock sync.Once  // Singleton support for opening sockets as needed
	sockets       []net.Conn // Opened sockets, if any

	// Command: podman _machine_
	kubectlCmd = &cobra.Command{
		Use:               "kubectl",
		Short:             "Shortcut for kubectl commands",
		Long:              "Shortcut for kubectl commands",
		PersistentPreRunE: machinePreRunE,
		RunE:              executeCmd,
	}
)

var (
	provider           vmconfigs.VMProvider
	defaultMachineName = define.DefaultMachineName
)

func init() {
	registry.Commands = append(registry.Commands, registry.CliCommand{
		Command: kubectlCmd,
	})
}
func machinePreRunE(c *cobra.Command, args []string) error {
	var err error
	provider, err = provider2.Get()
	if err != nil {
		return err
	}
	return nil
}
func executeCmd(cmd *cobra.Command, args []string) error {
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

	state, err := provider.State(mc, false)
	if err != nil {
		return err
	}
	if state != define.Running {
		return fmt.Errorf("vm %q is not running", mc.Name)
	}

	cmdArgs := []string{"sudo k3s kubectl " + strings.Join(args, " ")}
	err = machine.CommonSSHShell(mc.SSH.RemoteUsername, mc.SSH.IdentityPath, mc.Name, mc.SSH.Port, cmdArgs)
	return utils.HandleOSExecError(err)
}
