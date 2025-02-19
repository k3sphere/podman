//go:build amd64 || arm64

package k3s

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"

	"github.com/containers/image/v5/pkg/docker/config"
	"github.com/containers/image/v5/types"
	"github.com/containers/podman/v5/cmd/podman/registry"
	define2 "github.com/containers/podman/v5/pkg/k3s/define"
	"github.com/containers/podman/v5/pkg/machine/define"
	"github.com/containers/podman/v5/pkg/machine/env"
	"github.com/containers/podman/v5/pkg/machine/vmconfigs"
	"github.com/spf13/cobra"
)

type Payload struct {
	IP      string `json:"ip"`
	PublicKey  string `json:"publicKey"`
	Host    string `json:"host"`
	OIDC    bool   `json:"oidc"`
}

type Body struct {
	SwarmKey string `json:"swarmKey"`
	Token    string `json:"token"`
	Error    string `json:"error"`
	Relay    string `json:"relay"`
	VLAN     string `json:"vlan"`
}

var (
	registerCmd = &cobra.Command{
		Use:               "register [options] [MACHINE]",
		Short:             "Register the VM to the cdn",
		Long:              "Register the VM to the cdn",
		PersistentPreRunE: machinePreRunE,
		RunE:              register,
		Args:              cobra.MaximumNArgs(1),
		Example:           `podman machine register podman-machine-default`,
		ValidArgsFunction: autocompleteMachine,
	}
)

var (
	registerOptions define2.RegisterOptions
)

func init() {
	registry.Commands = append(registry.Commands, registry.CliCommand{
		Command: registerCmd,
		Parent:  k3sCmd,
	})



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

	state, err := provider.State(mc, false)
	if err != nil {
		return err
	}
	if state != define.Stopped {
		return fmt.Errorf("vm %q is running", mc.Name)
	}


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
	url := "https://k3sphere.com/api/machine/register"

	base64Data := fmt.Sprintf("%s:%s",dockerConfig.Username, dockerConfig.Password)
	token := base64.StdEncoding.EncodeToString([]byte(base64Data))

	// Data to be sent in JSON format
	data := Payload{
		IP:      mc.IP,
		Host:    mc.ID,
		OIDC:    false,

	}

	// Marshal the data to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		os.Exit(1)
	}

	// Create a new HTTP POST request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error creating request:", err)
		os.Exit(1)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Basic "+token)
	// Dump the request before sending
//	requestDump, err := httputil.DumpRequestOut(req, true)
//	if err != nil {
//		fmt.Println("Error dumping request:", err)
//	} else {
//		fmt.Println("HTTP Request:\n", string(requestDump))
//	}
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
	var result Body
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Println("Error decoding response:", err)
		os.Exit(1)
	}
	fmt.Println(resp)
	if result.Error != "" {
		fmt.Println("error happend ", result.Error)
	} else {
		mc.Lock()
		defer mc.Unlock()
		mc.Relay = result.Relay
		mc.SwarmKey = result.SwarmKey
		mc.VLAN = result.VLAN
		mc.Write()
		fmt.Println("successfully registered the machine")
	}
	return nil
}

func setRegistriesConfPath(systemContext *types.SystemContext) {
	if systemContext.SystemRegistriesConfPath != "" {
		return
	}
	if envOverride, ok := os.LookupEnv("CONTAINERS_REGISTRIES_CONF"); ok {
		systemContext.SystemRegistriesConfPath = envOverride
		return
	}
	if envOverride, ok := os.LookupEnv("REGISTRIES_CONFIG_PATH"); ok {
		systemContext.SystemRegistriesConfPath = envOverride
		return
	}
}
