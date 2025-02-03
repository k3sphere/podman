//go:build windows
// +build windows

package network

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"github.com/containers/common/pkg/completion"
	"github.com/containers/podman/v5/cmd/podman/registry"
	"github.com/spf13/cobra"
)

var (
	forwardDescription = `forward port from WSL to host`
	forwardCommand     = &cobra.Command{
		Use:               "forward [options]",
		Aliases:           []string{"forward"},
		Args:              cobra.MaximumNArgs(2),
		Short:             "forward networks",
		Long:              forwardDescription,
		RunE:              forward,
		ValidArgsFunction: completion.AutocompleteNone,
		Example:           `podman network forward`,
	}
)

func init() {
	registry.Commands = append(registry.Commands, registry.CliCommand{
		Command: forwardCommand,
		Parent:  networkCmd,
	})

}

func forward(cmd *cobra.Command, args []string) error {
	var err error
	ip, err := GetPodmanContainerIP()
	if err != nil {
		fmt.Printf("Error getting IP address: %v\n", err)
		return err
	}

	command := "cmd.exe"
	cmdString := fmt.Sprintf(
		"/c netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=%s connectaddress=%s connectport=%s",
		args[0], ip, args[1],
	)

	// Execute the command with admin privileges
	err = runAsAdmin(command, cmdString)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Command executed with administrator privileges.")
	}
	return err
}

// ShellExecute function to run a command with admin privileges
func runAsAdmin(command string, arguments string) error {
	verb := syscall.StringToUTF16Ptr("runas")
	exe := syscall.StringToUTF16Ptr(command)
	args := syscall.StringToUTF16Ptr(arguments)
	dir := syscall.StringToUTF16Ptr(".")

	// Call ShellExecute
	ret, _, err := syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW").Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(exe)),
		uintptr(unsafe.Pointer(args)),
		uintptr(unsafe.Pointer(dir)),
		syscall.SW_SHOWNORMAL,
	)

	if ret <= 32 {
		return fmt.Errorf("failed to elevate process: %v", err)
	}
	return nil
}

// GetPodmanContainerIP runs the WSL command to extract the IP address
func GetPodmanContainerIP() (string, error) {
	// Run the command
	cmd := exec.Command("wsl", "-d", "podman-net-usermode", "ip", "addr", "show", "eth0")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("error executing command: %v", err)
	}

	// Process the output to extract the IP address
	output := out.String()
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		// Find the line containing the IP address
		if strings.Contains(line, "inet ") {
			// Split the line and get the IP address before the slash
			parts := strings.Fields(line)
			ipWithCIDR := parts[1]
			ip := strings.Split(ipWithCIDR, "/")[0]
			return ip, nil
		}
	}

	return "", fmt.Errorf("IP address not found")
}
