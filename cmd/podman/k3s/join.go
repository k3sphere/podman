//go:build amd64 || arm64

package k3s

import (
	"bytes"
	"fmt"
	"html/template"

	"github.com/containers/common/pkg/completion"
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
	joinCmd = &cobra.Command{
		Use:               "join [options] [NAME] [COMMAND [ARG ...]]",
		Short:             "join k3s cluster",
		Long:              "join k3s cluster",
		PersistentPreRunE: machinePreRunE,
		RunE:              join,
		Example: `podman k3s join podman-machine-default
  podman k3s init`,
		ValidArgsFunction: autocompleteMachineSSH,
	}
)

var (
	joinOpts define.JoinOptions
)

func init() {
	joinCmd.Flags().SetInterspersed(false)
	registry.Commands = append(registry.Commands, registry.CliCommand{
		Command: joinCmd,
		Parent:  k3sCmd,
	})
	flags := joinCmd.Flags()

	TokenFlagName := "token"
	flags.StringVar(&joinOpts.Token, TokenFlagName, "", "Token used to join cluster")
	_ = initCmd.RegisterFlagCompletionFunc(TokenFlagName, completion.AutocompleteDefault)

}

// TODO Remember that this changed upstream and needs to updated as such!

func join(cmd *cobra.Command, args []string) error {
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
			joinOpts.Master = args[1]
		} else {
			//initOpts.Args = append(initOpts.Args, args[0])
			joinOpts.Master = args[0]
		}
	}

	// If the machine config was not loaded earlier, we load it now
	if mc == nil {
		mc, err = vmconfigs.LoadMachineByName(vmName, dirs)
		if err != nil {
			return fmt.Errorf("vm %s not found: %w", vmName, err)
		}
	}

	if !validVM && joinOpts.Username == "" {
		joinOpts.Username, err = remoteConnectionUsername()
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

	username := joinOpts.Username
	if username == "" {
		username = mc.SSH.RemoteUsername
	}

	tmpl := `curl -sfL https://get.k3s.io | K3S_URL="https://{{.Master}}:6443" K3S_TOKEN="{{.Token}}" sh -`

	// Parse the template
	t, err := template.New("shellCommand").Parse(tmpl)
	if err != nil {
		panic(err)
	}

	// Execute the template with the struct
	var result bytes.Buffer
	if err := t.Execute(&result, joinOpts); err != nil {
		panic(err)
	}

	joinOpts.Args = []string{result.String()}
	fmt.Println("command line: " + result.String())
	err = machine.CommonSSHShell(username, mc.SSH.IdentityPath, mc.Name, mc.SSH.Port, joinOpts.Args)
	return utils.HandleOSExecError(err)
}
