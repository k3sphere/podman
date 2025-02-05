//go:build amd64 || arm64

package machine

import (
	"bytes"
	"fmt"
	"net/http"
	"os"

	"github.com/containers/image/v5/pkg/docker/config"
	"github.com/containers/image/v5/types"
	"github.com/containers/podman/v5/cmd/podman/registry"
	"github.com/containers/podman/v5/pkg/machine"
	"github.com/containers/podman/v5/pkg/machine/env"
	"github.com/containers/podman/v5/pkg/machine/vmconfigs"
	"github.com/spf13/cobra"
)

type Payload struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	IP     string `json:"ip"`
	Region string `json:"region"`
}

type Body struct {
	SwarmKey string `json:"swarmKey"`
	Token    string `json:"token"`
	Error    string `json:"error"`
	Relay    string `json:"relay"`
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
	registerOptions machine.RegisterOptions
)

func init() {
	registry.Commands = append(registry.Commands, registry.CliCommand{
		Command: registerCmd,
		Parent:  machineCmd,
	})

	flags := registerCmd.Flags()
	nameFlagName := "name"
	flags.StringVar(&registerOptions.Name, nameFlagName, "", "name appears in portal for registration")

	regionFlagName := "region"
	flags.StringVar(&registerOptions.Region, regionFlagName, "eu", "region of cdn push zone (eu,us,asia)")

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

	if registerOptions.Name == "" {
		registerOptions.Name, _ = os.Hostname()
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
	url := "https://www.k3sphere.com/api/machine/register"

	// JWT Token
	token := dockerConfig.IdentityToken

	// Data to be sent in JSON format
	data := Payload{
		ID:     mc.ID,
		Name:   registerOptions.Name,
		Region: registerOptions.Region,
		IP:     mc.IP,
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
	req.Header.Set("Authorization", "Bearer "+token)

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
		fmt.Println("Please put the token below into your DNS TXT record with the same name as your domain")
		mc.Lock()
		defer mc.Unlock()
		mc.Relay = result.Relay
		mc.SwarmKey = result.SwarmKey
		mc.Write()
		fmt.Println(result.Token)
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
