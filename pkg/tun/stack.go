package tun

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"smartnet/pkg/config"
	"smartnet/pkg/fakeip"
	"smartnet/pkg/proxy"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Stack integrates a Virtual TUN adapter with a gVisor userspace network stack.
type Stack struct {
	cfg      *config.Config
	dev      *Device
	netstack *stack.Stack
	linkEP   *channel.Endpoint
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	mu       sync.Mutex
	closed   bool
}

// NewStack creates a new userspace network stack connected to a TUN interface.
func NewStack(cfg *config.Config) (*Stack, error) {
	mtu := 1500
	dev, err := CreateDevice(mtu)
	if err != nil {
		return nil, err
	}

	return NewStackWithDevice(cfg, dev)
}

// NewStackWithDevice creates a stack with a pre-created or mock Device.
func NewStackWithDevice(cfg *config.Config, dev *Device) (*Stack, error) {
	ctx, cancel := context.WithCancel(context.Background())

	linkEP := channel.New(512, uint32(dev.MTU()), "")

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})

	const nicID = tcpip.NICID(1)
	if err := s.CreateNIC(nicID, linkEP); err != nil {
		cancel()
		_ = dev.Close()
		return nil, fmt.Errorf("failed to create NIC in netstack: %v", err)
	}

	_ = s.SetPromiscuousMode(nicID, true)
	_ = s.SetSpoofing(nicID, true)
	s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})

	st := &Stack{
		cfg:      cfg,
		dev:      dev,
		netstack: s,
		linkEP:   linkEP,
		ctx:      ctx,
		cancel:   cancel,
	}

	// Register TCP forwarder
	tcpForwarder := tcp.NewForwarder(s, 0, 1024, st.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	// Register UDP forwarder
	udpForwarder := udp.NewForwarder(s, st.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	return st, nil
}

// Start begins processing TUN packets in the background.
func (st *Stack) Start() error {
	st.wg.Add(2)
	go st.pumpTUNToStack()
	go st.pumpStackToTUN()
	return nil
}

// DeviceName returns the OS network interface name.
func (st *Stack) DeviceName() string {
	if st.dev == nil {
		return ""
	}
	return st.dev.Name()
}

// Stop shuts down the stack and tears down network routes.
func (st *Stack) Stop() {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return
	}
	st.closed = true
	st.mu.Unlock()

	st.cancel()
	st.linkEP.Close()
	if st.dev != nil {
		_ = st.dev.Close()
	}
	st.netstack.Close()
	st.wg.Wait()
}

func (st *Stack) pumpTUNToStack() {
	defer st.wg.Done()

	const offset = 4
	bufs := make([][]byte, 1)
	bufs[0] = make([]byte, st.dev.MTU()+offset)
	sizes := make([]int, 1)

	for {
		select {
		case <-st.ctx.Done():
			return
		default:
		}

		n, err := st.dev.Read(bufs, sizes, offset)
		if err != nil {
			select {
			case <-st.ctx.Done():
				return
			default:
				time.Sleep(10 * time.Millisecond)
				continue
			}
		}
		if n == 0 || sizes[0] == 0 {
			continue
		}

		packetData := bufs[0][offset : offset+sizes[0]]
		if len(packetData) < 20 {
			continue
		}
		ipVer := packetData[0] >> 4
		if ipVer != 4 {
			continue
		}

		buf := buffer.MakeWithData(packetData)
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buf,
		})
		st.linkEP.InjectInbound(ipv4.ProtocolNumber, pkt)
		pkt.DecRef()
	}
}

func (st *Stack) pumpStackToTUN() {
	defer st.wg.Done()

	const offset = 4
	for {
		pkt := st.linkEP.ReadContext(st.ctx)
		if pkt == nil {
			return
		}

		view := pkt.ToView()
		pktBytes := view.AsSlice()
		if len(pktBytes) > 0 {
			outBuf := make([]byte, len(pktBytes)+offset)
			copy(outBuf[offset:], pktBytes)
			_, _ = st.dev.Write([][]byte{outBuf}, offset)
		}
		view.Release()
	}
}

func (st *Stack) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	destIP := net.IP(id.LocalAddress.AsSlice())
	destPort := id.LocalPort

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)

	conn := gonet.NewTCPConn(&wq, ep)
	go st.forwardTCP(conn, destIP, destPort)
}

type closeWriter interface {
	CloseWrite() error
}

func (st *Stack) forwardTCP(localConn net.Conn, destIP net.IP, destPort uint16) {
	defer localConn.Close()

	targetHost := destIP.String()
	if fakeip.DefaultPool.IsFakeIP(destIP) {
		if realDomain, found := fakeip.DefaultPool.LookupIP(destIP); found {
			targetHost = realDomain
		}
	}
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(int(destPort)))

	remoteConn, err := proxy.Dial(st.cfg, "tcp", targetAddr)
	if err != nil {
		return
	}
	defer remoteConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(remoteConn, localConn)
		if cw, ok := remoteConn.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = remoteConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		}
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(localConn, remoteConn)
		if cw, ok := localConn.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = localConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		}
	}()

	wg.Wait()
}

func (st *Stack) handleUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	destIP := net.IP(id.LocalAddress.AsSlice())
	destPort := id.LocalPort

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		return false
	}

	conn := gonet.NewUDPConn(&wq, ep)
	go st.forwardUDP(conn, destIP, destPort)
	return true
}

func (st *Stack) forwardUDP(localConn net.Conn, destIP net.IP, destPort uint16) {
	defer localConn.Close()

	targetHost := destIP.String()
	if fakeip.DefaultPool.IsFakeIP(destIP) {
		if realDomain, found := fakeip.DefaultPool.LookupIP(destIP); found {
			targetHost = realDomain
		}
	}
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(int(destPort)))

	remoteConn, err := proxy.Dial(st.cfg, "udp", targetAddr)
	if err != nil {
		return
	}
	defer remoteConn.Close()

	done := make(chan struct{}, 2)

	// local -> remote
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 65535)
		for {
			_ = localConn.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := localConn.Read(buf)
			if n > 0 {
				_ = remoteConn.SetWriteDeadline(time.Now().Add(60 * time.Second))
				if _, werr := remoteConn.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// remote -> local
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 65535)
		for {
			_ = remoteConn.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := remoteConn.Read(buf)
			if n > 0 {
				_ = localConn.SetWriteDeadline(time.Now().Add(60 * time.Second))
				if _, werr := localConn.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	<-done
}
