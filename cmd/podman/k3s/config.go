//go:build amd64 || arm64

package k3s

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/containers/image/v5/pkg/docker/config"
	"github.com/containers/image/v5/types"
	define "github.com/containers/podman/v5/pkg/k3s/define"

	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"

	"github.com/containers/podman/v5/cmd/podman/registry"
	"github.com/containers/podman/v5/cmd/podman/utils"
	"github.com/spf13/cobra"
)

var (
	configCmd = &cobra.Command{
		Use:               "config [options] [NAME] [COMMAND [ARG ...]]",
		Short:             "generate kubernetes config",
		Long:              "generate kubernetes config",
		PersistentPreRunE: machinePreRunE,
		RunE:              config1,
		Example: `podman k3s config podman-machine-default
  podman k3s config`,
		ValidArgsFunction: autocompleteMachineSSH,
	}
)

var (
	configOpts define.ConfigOptions
)

func init() {
	configCmd.Flags().SetInterspersed(false)
	registry.Commands = append(registry.Commands, registry.CliCommand{
		Command: configCmd,
		Parent:  k3sCmd,
	})
	flags := configCmd.Flags()
	clientIdFlagName := "client-id"
	flags.StringVar(&configOpts.ClientId, clientIdFlagName, "", "oidc client id")
	clientSecretFlagName := "client-secret"
	flags.StringVar(&configOpts.ClientSecret, clientSecretFlagName, "", "oidc client secret")
	commandFlagName := "command"
	flags.StringVar(&configOpts.Command, commandFlagName, "kubectl-oidc_login", "kubelogin command")
}

// TODO Remember that this changed upstream and needs to updated as such!

func config1(cmd *cobra.Command, args []string) error {

	if configOpts.ClientId == "" {
		skipTLS := types.NewOptionalBool(true)
		sysCtx := &types.SystemContext{
			DockerInsecureSkipTLSVerify: skipTLS,
		}
		setRegistriesConfPath(sysCtx)

		dockerConfig, err := config.GetCredentials(sysCtx, "k3sphere.com")
		if err != nil {
			return err
		}
		configOpts.ClientId = dockerConfig.Username
		configOpts.ClientSecret = dockerConfig.Password

	}
	// API endpoint URL
	url := "https://k3sphere.com/api/cluster/" + configOpts.ClientId

	base64Data := fmt.Sprintf("%s:%s",configOpts.ClientId, configOpts.ClientSecret)
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

	if resp.StatusCode != 200 {
		fmt.Println("failed to get cluster information, please try later")
		return nil
	} 

	fmt.Println("successfully registered the cluster")
	// extract name of the cluster from the http response json data
	var responseData struct {
		Name string `json:"name"`
		PublicKey string `json:"publicKey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
		fmt.Println("Error decoding response:", err)
		return nil
	}
	fmt.Println("Cluster Name:", responseData.Name)
	fmt.Println("PublicKey:", responseData.PublicKey)
	initOpts.Name = responseData.Name
	// Decode the Base64 CA certificate
	caCertData, err := base64.StdEncoding.DecodeString(responseData.PublicKey)
	if err != nil {
		return nil
	}
	newKubeConfig := &api.Config{
		Clusters: map[string]*api.Cluster{
			responseData.Name: {
				Server:                   fmt.Sprintf("https://api.%s.k3sphere.io",responseData.Name),
				CertificateAuthorityData:  caCertData,
			},
		},
		AuthInfos: map[string]*api.AuthInfo{
			responseData.Name: {
				Exec: &api.ExecConfig{
					Command: configOpts.Command,
					Args: []string{
						"get-token",
						"--oidc-issuer-url=https://auth.k3sphere.com/realms/k3sphere",
						"--oidc-client-id="+configOpts.ClientId,
						"--oidc-extra-scope=openid",
					},
					APIVersion: "client.authentication.k8s.io/v1beta1",
				},
			},
		},
		Contexts: map[string]*api.Context{
			responseData.Name: {
				Cluster:  responseData.Name,
				AuthInfo: responseData.Name,
			},
		},
		CurrentContext: responseData.Name,
	}

	// Merge the captured kubeconfig JSON into the current kubeconfig
	if err := mergeKubeconfig(newKubeConfig); err != nil {
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

func mergeKubeconfig(newKubeConfig *api.Config) error {


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
