package child

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/rootless-containers/rootlesskit/v2/pkg/lowlevelmsgutil"
	"github.com/rootless-containers/rootlesskit/v2/pkg/port"
	"github.com/rootless-containers/rootlesskit/v2/pkg/port/builtin/msg"
	opaquepkg "github.com/rootless-containers/rootlesskit/v2/pkg/port/builtin/opaque"
)

func NewDriver(logWriter io.Writer) port.ChildDriver {
	return &childDriver{
		logWriter: logWriter,
	}
}

type childDriver struct {
	logWriter io.Writer
}

func (d *childDriver) RunChildDriver(opaque map[string]string, quit <-chan struct{}, detachedNetNSPath string) error {
	socketPath := opaque[opaquepkg.SocketPath]
	if socketPath == "" {
		return errors.New("socket path not set")
	}
	childReadyPipePath := opaque[opaquepkg.ChildReadyPipePath]
	if childReadyPipePath == "" {
		return errors.New("child ready pipe path not set")
	}
	childReadyPipeW, err := os.OpenFile(childReadyPipePath, os.O_WRONLY, os.ModeNamedPipe)
	if err != nil {
		return err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{
		Name: socketPath,
		Net:  "unix",
	})
	if err != nil {
		return err
	}
	// write nothing, just close
	if err = childReadyPipeW.Close(); err != nil {
		return err
	}
	stopAccept := make(chan struct{}, 1)
	go func() {
		<-quit
		stopAccept <- struct{}{}
		ln.Close()
	}()
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			select {
			case <-stopAccept:
				return nil
			default:
			}
			return err
		}
		go func() {
			if rerr := d.routine(c, detachedNetNSPath); rerr != nil {
				rep := msg.Reply{
					Error: rerr.Error(),
				}
				lowlevelmsgutil.MarshalToWriter(c, &rep)
			}
			c.Close()
		}()
	}
}

func (d *childDriver) routine(c *net.UnixConn, detachedNetNSPath string) error {
	var req msg.Request
	if _, err := lowlevelmsgutil.UnmarshalFromReader(c, &req); err != nil {
		return err
	}
	switch req.Type {
	case msg.RequestTypeInit:
		return d.handleConnectInit(c, &req)
	case msg.RequestTypeConnect:
		if detachedNetNSPath == "" {
			return d.handleConnectRequest(c, &req)
		} else {
			return ns.WithNetNSPath(detachedNetNSPath, func(_ ns.NetNS) error {
				return d.handleConnectRequest(c, &req)
			})
		}
	default:
		return fmt.Errorf("unknown request type %q", req.Type)
	}
}

func (d *childDriver) handleConnectInit(c *net.UnixConn, req *msg.Request) error {
	_, err := lowlevelmsgutil.MarshalToWriter(c, nil)
	return err
}

func (d *childDriver) handleConnectRequest(c *net.UnixConn, req *msg.Request) error {
	switch req.Proto {
	case "tcp":
	case "tcp4":
	case "tcp6":
	case "udp":
	case "udp4":
	case "udp6":
	default:
		return fmt.Errorf("unknown proto: %q", req.Proto)
	}
	// dialProto does not need "4", "6" suffix
	dialProto := strings.TrimSuffix(strings.TrimSuffix(req.Proto, "6"), "4")
	var dialer net.Dialer
	ip := req.IP
	if ip == "" {
		ip = "127.0.0.1"
		if req.ParentIP != "" {
			if req.ParentIP != req.HostGatewayIP && req.ParentIP != "0.0.0.0" {
				ip = req.ParentIP
			}
		}
	} else {
		p := net.ParseIP(ip)
		if p == nil {
			return fmt.Errorf("invalid IP: %q", ip)
		}
		ip = p.String()
	}
	targetConn, err := dialer.Dial(dialProto, net.JoinHostPort(ip, strconv.Itoa(req.Port)))
	if err != nil {
		return err
	}
	defer targetConn.Close() // no effect on duplicated FD
	targetConnFiler, ok := targetConn.(filer)
	if !ok {
		return fmt.Errorf("unknown target connection: %+v", targetConn)
	}
	targetConnFile, err := targetConnFiler.File()
	if err != nil {
		return err
	}
	defer targetConnFile.Close()
	oob := unix.UnixRights(int(targetConnFile.Fd()))
	f, err := c.File()
	if err != nil {
		return err
	}
	defer f.Close()
	for {
		err = unix.Sendmsg(int(f.Fd()), []byte("dummy"), oob, nil, 0)
		if err != unix.EINTR {
			break
		}
	}
	return err
}

// filer is implemented by *net.TCPConn and *net.UDPConn
type filer interface {
	File() (f *os.File, err error)
}
