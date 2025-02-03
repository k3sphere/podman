//go:build windows

package wsl

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/containers/podman/v5/pkg/machine"
	"github.com/containers/podman/v5/pkg/machine/env"
	"github.com/containers/podman/v5/pkg/machine/vmconfigs"
	"github.com/containers/podman/v5/pkg/machine/wsl/wutil"
	"github.com/containers/podman/v5/pkg/specgen"
	"github.com/sirupsen/logrus"
)

const gvForwarderPath = "/usr/libexec/podman/gvforwarder"

const startUserModeNet = `
set -e
STATE=/mnt/wsl/podman-usermodenet
mkdir -p $STATE
cp -f /mnt/wsl/resolv.conf $STATE/resolv.orig
ip route show default > $STATE/route.dat
ROUTE=$(<$STATE/route.dat)
if [[ $ROUTE =~ .*$ROUTE_PATTERN.* ]]; then
	exit 2
fi
if [[ ! $ROUTE =~ default\ via ]]; then
	exit 3
fi
nohup $GVFORWARDER -iface podman-usermode -stop-if-exist ignore -url "stdio:$GVPROXY?listen-stdio=accept" > /var/log/vm.log 2> /var/log/vm.err  < /dev/null &
echo $! > $STATE/vm.pid
sleep 1
ps -eo args | grep -q -m1 ^$GVFORWARDER || exit 42
`

const stopUserModeNet = `
STATE=/mnt/wsl/podman-usermodenet
if [[ ! -f "$STATE/vm.pid" || ! -f "$STATE/route.dat" ]]; then
	exit 2
fi
cp -f $STATE/resolv.orig /mnt/wsl/resolv.conf
GPID=$(<$STATE/vm.pid)
kill $GPID > /dev/null
while kill -0 $GPID > /dev/null 2>&1; do
	sleep 1
done
ip route del default > /dev/null 2>&1
ROUTE=$(<$STATE/route.dat)
if [[ ! $ROUTE =~ default\ via ]]; then
	exit 3
fi
ip route add $ROUTE
rm -rf /mnt/wsl/podman-usermodenet
`

func verifyWSLUserModeCompat() error {
	if wutil.IsWSLStoreVersionInstalled() {
		return nil
	}

	prefix := ""
	if !winVersionAtLeast(10, 0, 19043) {
		prefix = "upgrade to 22H2, "
	}

	return fmt.Errorf("user-mode networking requires a newer version of WSL: "+
		"%sapply all outstanding windows updates, and then run `wsl --update`",
		prefix)
}

func startUserModeNetworking(mc *vmconfigs.MachineConfig) error {
	if !mc.WSLHypervisor.UserModeNetworking {
		return nil
	}

	exe, err := machine.FindExecutablePeer(gvProxy)
	if err != nil {
		return fmt.Errorf("could not locate %s, which is necessary for user-mode networking, please reinstall", gvProxy)
	}

	flock, err := obtainUserModeNetLock()
	if err != nil {
		return err
	}
	defer func() {
		_ = flock.unlock()
	}()

	running, err := isWSLRunning(userModeDist)
	if err != nil {
		return err
	}
	running = running && isGvProxyVMRunning()

	// Start or reuse
	if !running {
		env := os.Environ()                                        // Inherit parent environment
		env = append(env, fmt.Sprintf("ip=%s", mc.IP))             // Add custom variable
		env = append(env, fmt.Sprintf("subnet=%s", mc.Subnet))     // Add custom variable
		env = append(env, fmt.Sprintf("vlan=%s", mc.VLAN))         // Add custom variable
		env = append(env, fmt.Sprintf("password=%s", mc.Password)) // Add custom variable
		env = append(env, fmt.Sprintf("key=%s", mc.Key))           // Add custom variable
		env = append(env, fmt.Sprintf("relay=%s", mc.Relay))       // Add custom variable
		if err := launchUserModeNetDist(exe, mc.Subnet, env); err != nil {
			return err
		}
	}

	gateway, err := getGatewayIP(mc.Subnet)
	if err != nil {
		return err
	}
	if err := createUserModeResolvConf(env.WithPodmanPrefix(mc.Name), gateway); err != nil {
		return err
	}

	// Register in-use
	err = addUserModeNetEntry(mc)
	if err != nil {
		return err
	}

	return nil
}

func stopUserModeNetworking(mc *vmconfigs.MachineConfig) error {
	if !mc.WSLHypervisor.UserModeNetworking {
		return nil
	}

	flock, err := obtainUserModeNetLock()
	if err != nil {
		return err
	}
	defer func() {
		_ = flock.unlock()
	}()

	err = removeUserModeNetEntry(mc.Name)
	if err != nil {
		return err
	}

	count, err := cleanupAndCountNetEntries()
	if err != nil {
		return err
	}

	// Leave running if still in-use
	if count > 0 {
		return nil
	}

	fmt.Println("Stopping user-mode networking...")

	err = wslPipe(stopUserModeNet, userModeDist, []string{}, "bash")
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			switch exitErr.ExitCode() {
			case 2:
				err = fmt.Errorf("startup state was missing")
			case 3:
				err = fmt.Errorf("route state is missing a default route")
			}
		}
		logrus.Warnf("problem tearing down user-mode networking cleanly, forcing: %s", err.Error())
	}

	return terminateDist(userModeDist)
}

func isGvProxyVMRunning() bool {
	cmd := fmt.Sprintf("ps -eo args | grep -q -m1 ^%s || exit 42", gvForwarderPath)
	return wslInvoke(userModeDist, "bash", "-c", cmd) == nil
}

func launchUserModeNetDist(exeFile string, subnet string, env []string) error {
	fmt.Println("Starting user-mode networking...")

	exe, err := specgen.ConvertWinMountPath(exeFile)
	if err != nil {
		return err
	}

	gateway, err := getGatewayIP(subnet)
	if err != nil {
		return err
	}
	cmdStr := fmt.Sprintf("GVPROXY=%q\nGVFORWARDER=%q\nROUTE_PATTERN=%q\n%s", exe, gvForwarderPath, strings.ReplaceAll(gateway, ".", `\.`), startUserModeNet)
	if err := wslPipe(cmdStr, userModeDist, env, "bash"); err != nil {
		_ = terminateDist(userModeDist)

		if exitErr, ok := err.(*exec.ExitError); ok {
			switch exitErr.ExitCode() {
			case 2:
				return fmt.Errorf("another user-mode network is running, only one can be used at a time: shut down all machines and run wsl --shutdown if this is unexpected")
			case 3:
				err = fmt.Errorf("route state is missing a default route: shutdown all machines and run wsl --shutdown to recover")
			}
		}

		return fmt.Errorf("error setting up user-mode networking: %w", err)
	}

	return nil
}

func installUserModeDist(dist string, imagePath string) error {
	if err := verifyWSLUserModeCompat(); err != nil {
		return err
	}

	exists, err := isWSLExist(userModeDist)
	if err != nil {
		return err
	}

	if exists {
		if err := wslInvoke(userModeDist, "test", "-f", gvForwarderPath); err != nil {
			fmt.Println("Replacing old user-mode distribution...")
			_ = terminateDist(userModeDist)
			if err := unregisterDist(userModeDist); err != nil {
				return err
			}
			exists = false
		}
	}

	if !exists {
		if err := wslInvoke(dist, "test", "-f", gvForwarderPath); err != nil {
			return fmt.Errorf("existing machine is too old, can't install user-mode networking dist until machine is reinstalled (using podman machine rm, then podman machine init)")
		}

		const prompt = "Installing user-mode networking distribution..."
		if _, err := provisionWSLDist(userModeDist, imagePath, prompt); err != nil {
			return err
		}

		_ = terminateDist(userModeDist)
	}

	return nil
}

func createUserModeResolvConf(dist string, gateway string) error {
	err := wslPipe("nameserver "+gateway, dist, []string{}, "bash", "-c", "(rm -f /etc/resolv.conf; cat > /etc/resolv.conf)")
	if err != nil {
		return fmt.Errorf("could not create resolv.conf: %w", err)
	}
	return err
}

func getUserModeNetDir() (string, error) {
	vmDataDir, err := env.GetDataDir(vmtype)
	if err != nil {
		return "", err
	}

	dir := filepath.Join(vmDataDir, userModeDist)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("could not create %s directory: %w", userModeDist, err)
	}

	return dir, nil
}

func getUserModeNetEntriesDir() (string, error) {
	netDir, err := getUserModeNetDir()
	if err != nil {
		return "", err
	}

	dir := filepath.Join(netDir, "entries")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("could not create %s/entries directory: %w", userModeDist, err)
	}

	return dir, nil
}

func addUserModeNetEntry(mc *vmconfigs.MachineConfig) error {
	entriesDir, err := getUserModeNetEntriesDir()
	if err != nil {
		return err
	}

	path := filepath.Join(entriesDir, env.WithPodmanPrefix(mc.Name))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("could not add user-mode networking registration: %w", err)
	}
	file.Close()
	return nil
}

func removeUserModeNetEntry(name string) error {
	entriesDir, err := getUserModeNetEntriesDir()
	if err != nil {
		return err
	}

	path := filepath.Join(entriesDir, env.WithPodmanPrefix(name))
	return os.Remove(path)
}

func cleanupAndCountNetEntries() (uint, error) {
	entriesDir, err := getUserModeNetEntriesDir()
	if err != nil {
		return 0, err
	}

	allDists, err := getAllWSLDistros(true)
	if err != nil {
		return 0, err
	}

	var count uint = 0
	files, err := os.ReadDir(entriesDir)
	if err != nil {
		return 0, err
	}

	for _, file := range files {
		_, running := allDists[file.Name()]
		if !running {
			_ = os.Remove(filepath.Join(entriesDir, file.Name()))
			continue
		}
		count++
	}

	return count, nil
}

func obtainUserModeNetLock() (*fileLock, error) {
	dir, err := getUserModeNetDir()

	if err != nil {
		return nil, err
	}

	var flock *fileLock
	lockPath := filepath.Join(dir, "podman-usermodenet.lck")
	if flock, err = lockFile(lockPath); err != nil {
		return nil, fmt.Errorf("could not lock user-mode networking lock file: %w", err)
	}

	return flock, nil
}

func changeDistUserModeNetworking(dist string, user string, image string, enable bool) error {
	// Only install if user-mode is being enabled and there was an image path passed
	if enable {
		if len(image) == 0 {
			return errors.New("existing machine configuration is corrupt, no image is defined")
		}
		if err := installUserModeDist(dist, image); err != nil {
			return err
		}
	}

	if err := writeWslConf(dist, user); err != nil {
		return err
	}

	if enable {
		return appendDisableAutoResolve(dist)
	}

	return nil
}

func appendDisableAutoResolve(dist string) error {
	if err := wslPipe(wslConfUserNet, dist, []string{}, "sh", "-c", "cat >> /etc/wsl.conf"); err != nil {
		return fmt.Errorf("could not append resolv config to wsl.conf: %w", err)
	}

	return nil
}

func getGatewayIP(cidr string) (string, error) {
	// Parse the CIDR block
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR: %v", err)
	}

	// Get the network address as a 4-byte slice
	ip := ipNet.IP.To4()
	if ip == nil {
		return "", fmt.Errorf("not an IPv4 CIDR: %s", cidr)
	}

	// Increment the last byte to get the gateway IP
	ip[3]++

	// Check if the incremented IP is still within the subnet
	if !ipNet.Contains(ip) {
		return "", fmt.Errorf("invalid gateway for subnet: %s", cidr)
	}

	return ip.String(), nil
}
