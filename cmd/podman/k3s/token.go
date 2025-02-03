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
	tokenCmd = &cobra.Command{
		Use:               "token [options] [NAME] [COMMAND [ARG ...]]",
		Short:             "get k3s joining token",
		Long:              "get k3s joining token",
		PersistentPreRunE: machinePreRunE,
		RunE:              token,
		Example: `podman k3s token podman-machine-default
  podman k3s token`,
		ValidArgsFunction: autocompleteMachineSSH,
	}
)

var (
	tokenOpts define.InitOptions
)

func init() {
	tokenCmd.Flags().SetInterspersed(false)
	registry.Commands = append(registry.Commands, registry.CliCommand{
		Command: tokenCmd,
		Parent:  k3sCmd,
	})

}

// TODO Remember that this changed upstream and needs to updated as such!

func token(cmd *cobra.Command, args []string) error {
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

	initOpts.Args = []string{"sudo cat /var/lib/rancher/k3s/server/node-token"}
	err = machine.CommonSSHShell(username, mc.SSH.IdentityPath, mc.Name, mc.SSH.Port, initOpts.Args)
	return utils.HandleOSExecError(err)
}
