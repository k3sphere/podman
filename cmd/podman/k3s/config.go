//go:build amd64 || arm64

package k3s

import (
	"fmt"
	"os"
	"path/filepath"

	define "github.com/containers/podman/v5/pkg/k3s/define"
	define2 "github.com/containers/podman/v5/pkg/machine/define"
	"github.com/containers/podman/v5/pkg/machine/env"

	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"

	"github.com/containers/podman/v5/cmd/podman/registry"
	"github.com/containers/podman/v5/cmd/podman/utils"
	"github.com/containers/podman/v5/pkg/machine"
	"github.com/containers/podman/v5/pkg/machine/vmconfigs"
	"github.com/spf13/cobra"
)

var (
	configCmd = &cobra.Command{
		Use:               "config [options] [NAME] [COMMAND [ARG ...]]",
		Short:             "generate kubernetes config",
		Long:              "generate kubernetes config",
		PersistentPreRunE: machinePreRunE,
		RunE:              config,
		Example: `podman k3s config podman-machine-default
  podman k3s config`,
		ValidArgsFunction: autocompleteMachineSSH,
	}
)

var (
	configOpts define.InitOptions
)

func init() {
	configCmd.Flags().SetInterspersed(false)
	registry.Commands = append(registry.Commands, registry.CliCommand{
		Command: configCmd,
		Parent:  k3sCmd,
	})

}

// TODO Remember that this changed upstream and needs to updated as such!

func config(cmd *cobra.Command, args []string) error {
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

	initOpts.Args = []string{"sudo cat /etc/rancher/k3s/k3s.yaml"}
	output, err := machine.CommonSSHShellString(username, mc.SSH.IdentityPath, mc.Name, mc.SSH.Port, initOpts.Args)
	if err != nil {
		fmt.Printf("Error capturing command output: %v\n", err)
		return err
	}

	// Merge the captured kubeconfig JSON into the current kubeconfig
	if err := mergeKubeconfig(output); err != nil {
		fmt.Printf("Error merging kubeconfig: %v\n", err)
		return err
	}

	return utils.HandleOSExecError(err)
}

func mergeKubeconfigs(currentConfig, newConfig *api.Config) *api.Config {
	mergedConfig := currentConfig.DeepCopy()

	// Merge clusters
	for clusterName, cluster := range newConfig.Clusters {
		mergedConfig.Clusters[clusterName] = cluster
	}

	// Merge contexts
	for contextName, context := range newConfig.Contexts {
		mergedConfig.Contexts[contextName] = context
	}

	// Merge auth infos (users)
	for authName, authInfo := range newConfig.AuthInfos {
		mergedConfig.AuthInfos[authName] = authInfo
	}

	// If the new config has a different current context, set it
	if newConfig.CurrentContext != "" {
		mergedConfig.CurrentContext = newConfig.CurrentContext
	}

	return mergedConfig
}

func mergeKubeconfig(newConfigBytes []byte) error {
	// Parse the new kubeconfig YAML
	fmt.Println(string(newConfigBytes))
	newKubeConfig, err := clientcmd.Load(newConfigBytes)
	if err != nil {
		return fmt.Errorf("failed to parse kubeconfig YAML: %v", err)
	}

	// Define the kubeconfig path
	kubeconfigPath := filepath.Join(os.Getenv("HOME"), ".kube", "config")

	var currentConfig *api.Config

	// Check if the file exists
	if _, err := os.Stat(kubeconfigPath); os.IsNotExist(err) {
		fmt.Printf("Kubeconfig file does not exist. Creating a new one at: %s\n", kubeconfigPath)

		// Ensure the .kube directory exists
		if err := os.MkdirAll(filepath.Dir(kubeconfigPath), 0755); err != nil {
			return fmt.Errorf("failed to create .kube directory: %v", err)
		}

		if err := clientcmd.WriteToFile(*newKubeConfig, kubeconfigPath); err != nil {
			return fmt.Errorf("failed to write merged kubeconfig: %v", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to check kubeconfig file: %v", err)
	} else {
		// Load the current kubeconfig
		currentConfig, err = clientcmd.LoadFromFile(kubeconfigPath)
		if err != nil {
			return fmt.Errorf("failed to load current kubeconfig: %v", err)
		}
		// Merge the configurations
		mergedConfig := mergeKubeconfigs(currentConfig, newKubeConfig)

		// Save the merged configuration back to the kubeconfig file
		if err := clientcmd.WriteToFile(*mergedConfig, kubeconfigPath); err != nil {
			return fmt.Errorf("failed to write merged kubeconfig: %v", err)
		}
	}

	return nil
}
