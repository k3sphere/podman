//go:build amd64 || arm64

package k3s

import (
	"fmt"

	define "github.com/containers/podman/v5/pkg/k3s/define"
	define2 "github.com/containers/podman/v5/pkg/machine/define"
	"github.com/containers/podman/v5/pkg/machine/env"

	"github.com/containers/podman/v5/cmd/podman/registry"
	"github.com/containers/podman/v5/cmd/podman/utils"
	"github.com/containers/podman/v5/pkg/machine"
	"github.com/containers/podman/v5/pkg/machine/vmconfigs"
	"github.com/spf13/cobra"
)

var (
	startCmd = &cobra.Command{
		Use:               "start [options] [NAME] [COMMAND [ARG ...]]",
		Short:             "start k3s cluster",
		Long:              "start k3s cluster",
		PersistentPreRunE: machinePreRunE,
		RunE:              start,
		Example: `podman k3s start podman-machine-default
  podman k3s start`,
		ValidArgsFunction: autocompleteMachineSSH,
	}
)

var (
	startOpts define.InitOptions
)

func init() {
	startCmd.Flags().SetInterspersed(false)
	registry.Commands = append(registry.Commands, registry.CliCommand{
		Command: startCmd,
		Parent:  k3sCmd,
	})

}

// TODO Remember that this changed upstream and needs to updated as such!

func start(cmd *cobra.Command, args []string) error {
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
			if len(args) > 1 {
				initOpts.Args = []string{"sudo systemctl start " + args[1]}
			} else {
				initOpts.Args = []string{"sudo systemctl start k3s"}
			}

		} else {
			//initOpts.Args = append(initOpts.Args, args[0])
			initOpts.Args = []string{"sudo systemctl start " + args[0]}
		}
	} else {
		initOpts.Args = []string{"sudo systemctl start k3s"}
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

	err = machine.CommonSSHShell(username, mc.SSH.IdentityPath, mc.Name, mc.SSH.Port, initOpts.Args)
	return utils.HandleOSExecError(err)
}
