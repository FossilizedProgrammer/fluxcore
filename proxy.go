package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// tunnelSource hands the proxy the tunnel that is currently up, or nil while
// the manager is reconnecting. Connections that should be tunnelled fail closed
// in that window; the listener itself never goes away.
type tunnelSource interface {
	currentTunnel() *Tunnel
}

// proxyServer serves SOCKS5 and HTTP on separate loopback listeners. Both
// protocols share the same routing decision, so split tunnelling behaves
// identically whichever one an app speaks. Keeping the listeners separate also
// lets clients configure independent ports without exposing either protocol on
// the other one.
type proxyServer struct {
	socksLn    net.Listener
	httpLn     net.Listener
	source     tunnelSource
	upstream   *upstream
	killSwitch bool
	verbose    bool

	splitMu sync.RWMutex
	split   *compiledSplit
}

func newProxyServer(socksListen, httpListen string, source tunnelSource, split *compiledSplit, upstream *upstream, killSwitch, verbose bool) (*proxyServer, error) {
	socksLn, err := net.Listen("tcp", socksListen)
	if err != nil {
		return nil, fmt.Errorf("listen for SOCKS5 on %s: %w", socksListen, err)
	}
	httpLn, err := net.Listen("tcp", httpListen)
	if err != nil {
		_ = socksLn.Close()
		return nil, fmt.Errorf("listen for HTTP on %s: %w", httpListen, err)
	}
	return &proxyServer{
		socksLn: socksLn, httpLn: httpLn, source: source, split: split,
		upstream: upstream, killSwitch: killSwitch, verbose: verbose,
	}, nil
}

func (p *proxyServer) SocksAddr() string { return p.socksLn.Addr().String() }

func (p *proxyServer) HTTPAddr() string { return p.httpLn.Addr().String() }

func (p *proxyServer) splitNow() *compiledSplit {
	p.splitMu.RLock()
	defer p.splitMu.RUnlock()
	return p.split
}

func (p *proxyServer) setSplit(c *compiledSplit) {
	p.splitMu.Lock()
	p.split = c
	p.splitMu.Unlock()
}

func (p *proxyServer) Serve() error {
	errCh := make(chan error, 2)
	go func() { errCh <- p.serve(p.socksLn, p.handleSOCKSConn) }()
	go func() { errCh <- p.serve(p.httpLn, p.handleHTTPConn) }()
	err := <-errCh
	_ = p.Close()
	return err
}

func (p *proxyServer) serve(ln net.Listener, handle func(net.Conn)) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go handle(conn)
	}
}

func (p *proxyServer) Close() error {
	socksErr := p.socksLn.Close()
	httpErr := p.httpLn.Close()
	if socksErr != nil && !errors.Is(socksErr, net.ErrClosed) {
		return socksErr
	}
	if httpErr != nil && !errors.Is(httpErr, net.ErrClosed) {
		return httpErr
	}
	return nil
}

func (p *proxyServer) logf(format string, args ...any) {
	if p.verbose {
		fmt.Printf("[proxy] "+format+"\n", args...)
	}
}

func (p *proxyServer) handleSOCKSConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	br := bufio.NewReaderSize(conn, 16*1024)
	if err := socksHandshake(conn, br); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	host, port, err := socksRequest(conn, br)
	if err != nil {
		return
	}
	target, direct, err := p.dial(context.Background(), host, port)
	if err != nil {
		p.logf("socks %s:%d: %v", host, port, err)
		writeSocksReply(conn, socksReplyFor(err))
		return
	}
	defer target.Close()
	if err := writeSocksReply(conn, 0x00); err != nil {
		return
	}
	p.logf("socks %s:%d direct=%v", host, port, direct)
	relay(conn, br, target)
}

func (p *proxyServer) handleHTTPConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	br := bufio.NewReaderSize(conn, 16*1024)
	p.handleHTTP(conn, br)
}

// ---- SOCKS5 ----------------------------------------------------------------

func socksHandshake(conn net.Conn, br *bufio.Reader) error {
	var head [2]byte
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return err
	}
	if head[0] != 0x05 {
		return fmt.Errorf("socks: unsupported version %d", head[0])
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return err
	}
	ok := false
	for _, m := range methods {
		if m == 0x00 {
			ok = true
		}
	}
	if !ok {
		_, _ = conn.Write([]byte{0x05, 0xFF})
		return fmt.Errorf("socks: client offered no acceptable auth method")
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return err
	}
	return nil
}

func socksRequest(conn net.Conn, br *bufio.Reader) (string, uint16, error) {
	var head [4]byte
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return "", 0, err
	}
	if head[0] != 0x05 {
		return "", 0, fmt.Errorf("socks: bad request version")
	}
	if head[1] != 0x01 { // CONNECT only; BIND and UDP ASSOCIATE are unsupported
		writeSocksReply(conn, 0x07)
		return "", 0, fmt.Errorf("socks: command %d not supported", head[1])
	}
	var host string
	switch head[3] {
	case 0x01:
		var b [4]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom4(b).String()
	case 0x04:
		var b [16]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom16(b).String()
	case 0x03:
		n, err := br.ReadByte()
		if err != nil {
			return "", 0, err
		}
		name := make([]byte, int(n))
		if _, err := io.ReadFull(br, name); err != nil {
			return "", 0, err
		}
		host = string(name)
	default:
		writeSocksReply(conn, 0x08)
		return "", 0, fmt.Errorf("socks: unknown address type %d", head[3])
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(br, portBytes[:]); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(portBytes[:]), nil
}

func writeSocksReply(conn net.Conn, code byte) error {
	// BND.ADDR is all-zero; every client accepts that for CONNECT.
	_, err := conn.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

func socksReplyFor(err error) byte {
	if errors.Is(err, errTunnelDown) {
		return 0x03 // network unreachable
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return 0x06 // TTL expired / timeout
	}
	return 0x05 // connection refused
}

// ---- HTTP ------------------------------------------------------------------

func (p *proxyServer) handleHTTP(conn net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	defer req.Body.Close()
	_ = conn.SetDeadline(time.Time{})

	if req.Method == http.MethodConnect {
		host, portStr, err := net.SplitHostPort(req.Host)
		if err != nil {
			host, portStr = req.Host, "443"
		}
		port, _ := strconv.Atoi(portStr)
		target, direct, err := p.dial(context.Background(), host, uint16(port))
		if err != nil {
			p.logf("http CONNECT %s: %v", req.Host, err)
			writeHTTPError(conn, 502, err)
			return
		}
		defer target.Close()
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		p.logf("http CONNECT %s direct=%v", req.Host, direct)
		relay(conn, br, target)
		return
	}

	// Absolute-form request ("GET http://host/path HTTP/1.1"), as sent to a
	// plain HTTP proxy.
	if req.URL == nil || req.URL.Host == "" {
		writeHTTPError(conn, 400, fmt.Errorf("expected a proxy request with an absolute URI"))
		return
	}
	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		if req.URL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	portNum, _ := strconv.Atoi(port)
	target, direct, err := p.dial(context.Background(), host, uint16(portNum))
	if err != nil {
		p.logf("http %s: %v", req.URL, err)
		writeHTTPError(conn, 502, err)
		return
	}
	defer target.Close()

	req.RequestURI = ""
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	if err := req.Write(target); err != nil {
		writeHTTPError(conn, 502, err)
		return
	}
	p.logf("http %s direct=%v", req.URL, direct)
	relay(conn, br, target)
}

func writeHTTPError(conn net.Conn, code int, err error) {
	body := "proxy error: " + err.Error() + "\n"
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
}

// ---- routing and dialing ---------------------------------------------------

var errTunnelDown = errors.New("tunnel is down; refusing to leak this connection")

// dial resolves the target, applies the split policy, and connects either
// through the tunnel's userspace stack or on a plain system socket.
func (p *proxyServer) dial(ctx context.Context, host string, port uint16) (net.Conn, bool, error) {
	if port == 0 {
		return nil, false, fmt.Errorf("missing port for %s", host)
	}
	t := p.source.currentTunnel()

	split := p.splitNow()
	var ip netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		ip = a.Unmap()
	} else if t != nil && split.excludedDNS != "system" {
		if a, err := lookupInTunnel(t, host); err == nil {
			ip = a
		}
	}
	direct := split.direct(host, ip)

	if direct {
		return p.dialDirect(ctx, host, port)
	}
	if t == nil {
		if p.killSwitch {
			return nil, false, errTunnelDown
		}
		return p.dialDirect(ctx, host, port)
	}
	if !ip.IsValid() {
		a, err := lookupInTunnel(t, host)
		if err != nil {
			return nil, false, fmt.Errorf("resolve %s through tunnel: %w", host, err)
		}
		ip = a
	}
	c, err := t.net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(ip, port))
	if err != nil {
		return nil, false, err
	}
	return c, false, nil
}

// dialDirect connects without the tunnel. With an upstream configured, even
// split-tunnel "direct" destinations go through the proxy: when the local path
// is filtered, a direct socket is exactly what does not work.
func (p *proxyServer) dialDirect(ctx context.Context, host string, port uint16) (net.Conn, bool, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	if p.upstream != nil {
		c, err := p.upstream.dialContext(ctx, "tcp", addr)
		return c, true, err
	}
	d := &net.Dialer{Timeout: 15 * time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	return c, true, err
}

// lookupInTunnel resolves a name with the gateway's DNS through the tunnel's
// userspace stack, so the query does not leak to the local resolver.
func lookupInTunnel(t *Tunnel, host string) (netip.Addr, error) {
	addrs, err := t.net.LookupHost(host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, s := range addrs {
		if a, err := netip.ParseAddr(s); err == nil {
			return a.Unmap(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no address for %s", host)
}

// ---- byte pump -------------------------------------------------------------

func relay(client net.Conn, clientBuf io.Reader, target net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(target, clientBuf)
		closeWrite(target)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, target)
		closeWrite(client)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
