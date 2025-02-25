//go:build amd64 || arm64

package machine

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/containers/image/v5/pkg/docker/config"
	"github.com/containers/image/v5/types"
	"github.com/containers/podman/v5/pkg/machine/define"
	"github.com/containers/podman/v5/pkg/machine/env"

	"github.com/containers/common/pkg/completion"
	"github.com/containers/podman/v5/cmd/podman/registry"
	"github.com/containers/podman/v5/cmd/podman/utils"
	"github.com/containers/podman/v5/pkg/machine"
	"github.com/containers/podman/v5/pkg/machine/vmconfigs"
	"github.com/spf13/cobra"
)

type TrustPayload struct {
	Machine      string `json:"machine"`
	Account    string `json:"account"`
}

type TrustBody struct {
	Keys    []string `json:"keys"`
}

type Key struct {
	Name string `json:"name"`
	PublicKey    string `json:"publicKey"`
}

var (
	trustCmd = &cobra.Command{
		Use:               "trust [options] [NAME] [COMMAND [ARG ...]]",
		Short:             "trust cloud account",
		Long:              "trust cloud account ",
		PersistentPreRunE: machinePreRunE,
		RunE:              trust,
		Args:              cobra.MaximumNArgs(2),
		Example: `podman machine trust podman-machine-default
  podman machine trust myvm test`,
		ValidArgsFunction: autocompleteMachineSSH,
	}
)

var (
	trustOpts machine.TrustOptions
)

func init() {
	trustCmd.Flags().SetInterspersed(false)
	registry.Commands = append(registry.Commands, registry.CliCommand{
		Command: trustCmd,
		Parent:  machineCmd,
	})
	flags := trustCmd.Flags()
	usernameFlagName := "username"
	flags.StringVar(&trustOpts.Username, usernameFlagName, "", "Username to use when ssh-ing into the VM.")
	_ = trustCmd.RegisterFlagCompletionFunc(usernameFlagName, completion.AutocompleteNone)

}

// TODO Remember that this changed upstream and needs to updated as such!

func trust(cmd *cobra.Command, args []string) error {
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
			trustOpts.Account = args[0]
		}
	}

	// If len is greater than 1, it means we might have been
	// given a vmname and args or just args
	if len(args) > 1 {
		if validVM {
			trustOpts.Account = args[1]
		} else {
			trustOpts.Account = args[0]
		}
	}

	// If the machine config was not loaded earlier, we load it now
	if mc == nil {
		mc, err = vmconfigs.LoadMachineByName(vmName, dirs)
		if err != nil {
			return fmt.Errorf("vm %s not found: %w", vmName, err)
		}
	}

	if !validVM && sshOpts.Username == "" {
		trustOpts.Username, err = remoteConnectionUsername()
		if err != nil {
			return err
		}
	}

	state, err := provider.State(mc, false)
	if err != nil {
		return err
	}
	if state != define.Running {
		return fmt.Errorf("vm %q is not running", mc.Name)
	}

	username := trustOpts.Username
	if username == "" {
		username = mc.SSH.RemoteUsername
	}

	// call backend api to fetch account keys to add

	skipTLS := types.NewOptionalBool(true)
	sysCtx := &types.SystemContext{
		DockerInsecureSkipTLSVerify: skipTLS,
	}
	setRegistriesConfPath(sysCtx)

	dockerConfig, err := config.GetCredentials(sysCtx, "k3sphere.com")
	if err != nil {
		return err
	}

	// API endpoint URL
	url := "https://k3sphere.com/api/machine/trust"

	base64Data := fmt.Sprintf("%s:%s",dockerConfig.Username, dockerConfig.Password)
	token := base64.StdEncoding.EncodeToString([]byte(base64Data))

	// Create a new HTTP POST request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		os.Exit(1)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Basic "+token)

	requestDump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		fmt.Println("Error dumping request:", err)
	} else {
		fmt.Println("HTTP Request:\n", string(requestDump))
	}
	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	// Print the response
	fmt.Println("Response Status:", resp.Status)
	var result TrustBody
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Println("Error decoding response:", err)
		os.Exit(1)
	}
	fmt.Println(resp)

	if len(result.Keys) > 0 {
		trustOpts.Args = []string {generateUserSetupCommand(mc.SSH.RemoteUsername, result.Keys)}
		err = machine.CommonSSHShell(username, mc.SSH.IdentityPath, mc.Name, mc.SSH.Port, trustOpts.Args)
		return utils.HandleOSExecError(err)
	}else {
		fmt.Println("Can't trust account without keys")
	}
	return nil
}

func generateUserSetupCommand(username string, keys []string) string {
	
	joinedKeys := ""
	for _, key := range keys {
		joinedKeys += key
	}

	cmd := fmt.Sprintf(`echo '%s' |  sudo tee -a /home/%s/.ssh/authorized_keys && (sudo grep -q '^PubkeyAcceptedAlgorithms' /etc/ssh/sshd_config || sudo sed -i '1s/^/AuthenticationMethods publickey\nPubkeyAcceptedAlgorithms +webauthn-sk-ecdsa-sha2-nistp256@openssh.com\n/' /etc/ssh/sshd_config && sudo systemctl restart sshd)`, joinedKeys, username)

	fmt.Println(cmd)
	return cmd
}

