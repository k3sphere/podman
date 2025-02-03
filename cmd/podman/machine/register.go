//go:build amd64 || arm64

package machine

import (
	"github.com/containers/podman/v5/cmd/podman/registry"
	"github.com/containers/podman/v5/libpod/events"
	"github.com/containers/podman/v5/pkg/machine"
	"github.com/containers/podman/v5/pkg/machine/env"
	"github.com/containers/podman/v5/pkg/machine/shim"
	"github.com/containers/podman/v5/pkg/machine/vmconfigs"
	"github.com/spf13/cobra"
)

var (
	registerCmd = &cobra.Command{
		Use:               "rm [options] [MACHINE]",
		Short:             "Remove an existing machine",
		Long:              "Remove a managed virtual machine ",
		PersistentPreRunE: machinePreRunE,
		RunE:              register,
		Args:              cobra.MaximumNArgs(1),
		Example:           `podman machine rm podman-machine-default`,
		ValidArgsFunction: autocompleteMachine,
	}
)

var (
	registerOptions machine.RegisterOptions
)

func init() {
	registry.Commands = append(registry.Commands, registry.CliCommand{
		Command: rmCmd,
		Parent:  machineCmd,
	})

	flags := rmCmd.Flags()
	nameFlagName := "name"
	flags.StringVar(&registerOptions.Name, nameFlagName, "", "name appears in portal for registration")

}

func register(_ *cobra.Command, args []string) error {
	var (
		err error
	)
	vmName := defaultMachineName
	if len(args) > 0 && len(args[0]) > 0 {
		vmName = args[0]
	}

	dirs, err := env.GetMachineDirs(provider.VMType())
	if err != nil {
		return err
	}

	mc, err := vmconfigs.LoadMachineByName(vmName, dirs)
	if err != nil {
		return err
	}

	if err := shim.Remove(mc, provider, dirs, destroyOptions); err != nil {
		return err
	}
	newMachineEvent(events.Remove, events.Event{Name: vmName})
	return nil
}
