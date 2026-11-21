package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
)

// upstream is an optional proxy that every outbound connection of the client is
// dialed through: discovery and gateway control requests, split-tunnel "direct"
// destinations, and the tunnel's own transport. A SOCKS5 upstream also carries
// WireGuard's UDP datagrams (UDP ASSOCIATE); HTTP/HTTPS upstreams only offer
// CONNECT, so UDP transports fall through to wg-tls.
type upstream struct {
	kind     string // "socks5" | "http" | "https"
	addr     string // host:port of the proxy
	user     string
	pass     string
	proxyURL *url.URL
}

func parseUpstream(raw string) (*upstream, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return nil, nil
	}
	if !strings.Contains(v, "://") {
		v = "socks5://" + v
	}
	u, err := url.Parse(v)
	if err != nil {
		return nil, fmt.Errorf("upstream %q: %w", raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "socks5", "socks5h":
		scheme = "socks5"
	case "http", "https":
	default:
		return nil, fmt.Errorf("upstream %q: unsupported scheme %q (use socks5:// or http://)", raw, u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("upstream %q: missing host", raw)
	}
	port := u.Port()
	if port == "" {
		switch scheme {
		case "socks5":
			port = "1080"
		case "https":
			port = "443"
		default:
			port = "8080"
		}
	}
	out := &upstream{kind: scheme, addr: net.JoinHostPort(host, port)}
	if u.User != nil {
		out.user = u.User.Username()
		out.pass, _ = u.User.Password()
	}
	out.proxyURL = &url.URL{Scheme: scheme, Host: out.addr}
	if out.user != "" || out.pass != "" {
		out.proxyURL.User = url.UserPassword(out.user, out.pass)
	}
	return out, nil
}

// display renders the upstream without its password.
func (u *upstream) display() string {
	p := *u.proxyURL
	if p.User != nil {
		p.User = url.User(p.User.Username())
	}
	return p.String()
}

// displayUpstream renders a configured upstream for humans, naming the disabled
// state explicitly.
func displayUpstream(raw string) string {
	up, err := parseUpstream(raw)
	if err != nil {
		return raw + " (invalid)"
	}
	if up == nil {
		return "none (direct)"
	}
	return up.display()
}

// supportsUDP reports whether this proxy can relay WireGuard datagrams.
func (u *upstream) supportsUDP() bool { return u.kind == "socks5" }

// dialContext opens a TCP connection to addr through the upstream proxy.
func (u *upstream) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("upstream %s cannot carry %s", u.kind, network)
	}
	d := &net.Dialer{Timeout: 15 * time.Second}
	c, err := d.DialContext(ctx, "tcp", u.addr)
	if err != nil {
		return nil, fmt.Errorf("upstream %s: %w", u.addr, err)
	}
	deadline := time.Now().Add(15 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	switch u.kind {
	case "socks5":
		err = u.socksConnect(c, addr)
	default:
		c, err = u.httpConnect(ctx, c, addr)
	}
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

// configureHTTPClient routes the shared control-plane client through up, or
// restores direct dialing when up is nil. net/http understands both http(s)
// and socks5 proxy URLs, including userinfo credentials.
func configureHTTPClient(up *upstream) {
	if up == nil {
		httpClient.Transport = nil
		return
	}
	httpClient.Transport = &http.Transport{
		Proxy:                 http.ProxyURL(up.proxyURL),
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
		TLSHandshakeTimeout:   12 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}
}

// ---- SOCKS5 ----------------------------------------------------------------

func socksMethodBytes(withAuth bool) []byte {
	if withAuth {
		return []byte{0x05, 0x02, 0x00, 0x02}
	}
	return []byte{0x05, 0x01, 0x00}
}

// socksGreet offers no-auth and, when credentials exist, username/password. It
// returns the method the proxy selected.
func socksGreet(c net.Conn, withAuth bool) (byte, error) {
	if _, err := c.Write(socksMethodBytes(withAuth)); err != nil {
		return 0, fmt.Errorf("socks5: greet: %w", err)
	}
	var sel [2]byte
	if _, err := io.ReadFull(c, sel[:]); err != nil {
		return 0, fmt.Errorf("socks5: greet reply: %w", err)
	}
	if sel[0] != 0x05 {
		return 0, fmt.Errorf("socks5: bad version %d", sel[0])
	}
	if sel[1] == 0xFF {
		return 0, errors.New("socks5: upstream rejected all auth methods")
	}
	return sel[1], nil
}

func socksAuthenticate(c net.Conn, user, pass string) error {
	if len(user) > 255 || len(pass) > 255 {
		return errors.New("socks5: username or password too long")
	}
	buf := []byte{0x01, byte(len(user))}
	buf = append(buf, user...)
	buf = append(buf, byte(len(pass)))
	buf = append(buf, pass...)
	if _, err := c.Write(buf); err != nil {
		return fmt.Errorf("socks5: auth: %w", err)
	}
	var r [2]byte
	if _, err := io.ReadFull(c, r[:]); err != nil {
		return fmt.Errorf("socks5: auth reply: %w", err)
	}
	if r[1] != 0x00 {
		return errors.New("socks5: upstream authentication failed")
	}
	return nil
}

// socksAddrBytes encodes host:port in the SOCKS5 address format.
func socksAddrBytes(host string, port uint16) []byte {
	out := make([]byte, 0, 1+16+2)
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		if a.Is4() {
			b := a.As4()
			out = append(out, 0x01)
			out = append(out, b[:]...)
		} else {
			b := a.As16()
			out = append(out, 0x04)
			out = append(out, b[:]...)
		}
	} else {
		if len(host) > 255 {
			host = host[:255]
		}
		out = append(out, 0x03, byte(len(host)))
		out = append(out, host...)
	}
	return append(out, byte(port>>8), byte(port))
}

func socksRequestBytes(cmd byte, host string, port uint16) []byte {
	req := []byte{0x05, cmd, 0x00}
	return append(req, socksAddrBytes(host, port)...)
}

// readSocksReply consumes a SOCKS5 reply and returns its BND.ADDR/BND.PORT.
func readSocksReply(c net.Conn) (string, uint16, error) {
	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return "", 0, fmt.Errorf("socks5: reply: %w", err)
	}
	if head[0] != 0x05 {
		return "", 0, fmt.Errorf("socks5: bad reply version %d", head[0])
	}
	if head[1] != 0x00 {
		return "", 0, fmt.Errorf("socks5: upstream refused the request (code %d)", head[1])
	}
	var host string
	switch head[3] {
	case 0x01:
		var b [4]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom4(b).String()
	case 0x04:
		var b [16]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom16(b).String()
	case 0x03:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return "", 0, err
		}
		name := make([]byte, int(n[0]))
		if _, err := io.ReadFull(c, name); err != nil {
			return "", 0, err
		}
		host = string(name)
	default:
		return "", 0, fmt.Errorf("socks5: unknown reply address type %d", head[3])
	}
	var port [2]byte
	if _, err := io.ReadFull(c, port[:]); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(port[:]), nil
}

func (u *upstream) socksConnect(c net.Conn, addr string) error {
	method, err := socksGreet(c, u.user != "" || u.pass != "")
	if err != nil {
		return err
	}
	if method == 0x02 {
		if err := socksAuthenticate(c, u.user, u.pass); err != nil {
			return err
		}
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("socks5: %w", err)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return fmt.Errorf("socks5: bad port %q", portStr)
	}
	if _, err := c.Write(socksRequestBytes(0x01, host, uint16(port))); err != nil {
		return fmt.Errorf("socks5: connect request: %w", err)
	}
	if _, _, err := readSocksReply(c); err != nil {
		return err
	}
	return nil
}

// ---- HTTP / HTTPS CONNECT --------------------------------------------------

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func (u *upstream) httpConnect(ctx context.Context, c net.Conn, addr string) (net.Conn, error) {
	if u.kind == "https" {
		tlsConn := tls.Client(c, &tls.Config{
			ServerName: strings.Split(u.addr, ":")[0],
			MinVersion: tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("upstream TLS handshake: %w", err)
		}
		c = tlsConn
	}
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if u.user != "" || u.pass != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(u.user + ":" + u.pass))
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", cred)
	}
	b.WriteString("Proxy-Connection: keep-alive\r\n\r\n")
	if _, err := io.WriteString(c, b.String()); err != nil {
		return nil, fmt.Errorf("upstream CONNECT: %w", err)
	}
	br := bufio.NewReader(c)
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: addr}}
	res, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, fmt.Errorf("upstream CONNECT reply: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream CONNECT %s: %s", addr, res.Status)
	}
	if br.Buffered() > 0 {
		return bufferedConn{Conn: c, r: br}, nil
	}
	return c, nil
}

// ---- SOCKS5 UDP ASSOCIATE --------------------------------------------------

// socksUDPAssociation relays datagrams to a single destination through a SOCKS5
// UDP ASSOCIATE relay. WireGuard has exactly one peer, so one association is
// enough; the TCP control connection keeps the association alive.
type socksUDPAssociation struct {
	ctrl   net.Conn
	udp    *net.UDPConn
	relay  *net.UDPAddr
	header []byte
	buf    []byte

	closeOnce sync.Once
	closed    chan struct{}
}

// socksAddrLen returns the encoded length of the SOCKS5 address (ATYP included)
// at the start of b, which is used for datagram de-encapsulation.
func socksAddrLen(b []byte) (int, bool) {
	if len(b) < 1 {
		return 0, false
	}
	switch b[0] {
	case 0x01:
		if len(b) < 1+4+2 {
			return 0, false
		}
		return 1 + 4 + 2, true
	case 0x04:
		if len(b) < 1+16+2 {
			return 0, false
		}
		return 1 + 16 + 2, true
	case 0x03:
		if len(b) < 2 {
			return 0, false
		}
		n := int(b[1])
		if len(b) < 1+1+n+2 {
			return 0, false
		}
		return 1 + 1 + n + 2, true
	}
	return 0, false
}

func (u *upstream) dialSocksUDP(target netip.AddrPort) (*socksUDPAssociation, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	d := &net.Dialer{Timeout: 15 * time.Second}
	ctrl, err := d.DialContext(ctx, "tcp", u.addr)
	if err != nil {
		return nil, fmt.Errorf("upstream %s: %w", u.addr, err)
	}
	fail := func(err error) (*socksUDPAssociation, error) {
		_ = ctrl.Close()
		return nil, err
	}
	_ = ctrl.SetDeadline(time.Now().Add(15 * time.Second))

	method, err := socksGreet(ctrl, u.user != "" || u.pass != "")
	if err != nil {
		return fail(err)
	}
	if method == 0x02 {
		if err := socksAuthenticate(ctrl, u.user, u.pass); err != nil {
			return fail(err)
		}
	}

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return fail(fmt.Errorf("socks5 udp: %w", err))
	}
	local := udp.LocalAddr().(*net.UDPAddr)
	if _, err := ctrl.Write(socksRequestBytes(0x03, local.IP.String(), uint16(local.Port))); err != nil {
		_ = udp.Close()
		return fail(fmt.Errorf("socks5 udp associate: %w", err))
	}
	host, port, err := readSocksReply(ctrl)
	if err != nil {
		_ = udp.Close()
		return fail(err)
	}

	// Many servers answer 0.0.0.0:port and expect the client to send to the
	// control connection's peer address instead.
	relayIP := net.ParseIP(host)
	if relayIP == nil && host != "" {
		if addrs, err := net.LookupIP(host); err == nil && len(addrs) > 0 {
			relayIP = addrs[0]
		}
	}
	if relayIP == nil || relayIP.IsUnspecified() {
		if ta, ok := ctrl.RemoteAddr().(*net.TCPAddr); ok {
			relayIP = ta.IP
		}
	}
	if relayIP == nil || port == 0 {
		_ = udp.Close()
		return fail(errors.New("socks5: upstream returned an unusable UDP relay address"))
	}
	_ = ctrl.SetDeadline(time.Time{})

	a := &socksUDPAssociation{
		ctrl:   ctrl,
		udp:    udp,
		relay:  &net.UDPAddr{IP: relayIP, Port: int(port)},
		header: socksAddrBytes(target.Addr().String(), target.Port()),
		buf:    make([]byte, 65535),
		closed: make(chan struct{}),
	}
	go a.watch()
	return a, nil
}

// watch tears the association down when the control connection dies; the
// relay's datagram mapping is scoped to that connection.
func (a *socksUDPAssociation) watch() {
	buf := make([]byte, 512)
	for {
		if _, err := a.ctrl.Read(buf); err != nil {
			_ = a.Close()
			return
		}
	}
}

func (a *socksUDPAssociation) Write(p []byte) (int, error) {
	pkt := make([]byte, 3+len(a.header)+len(p))
	// RSV(2) + FRAG(1) are zero: no fragmentation.
	copy(pkt[3:], a.header)
	copy(pkt[3+len(a.header):], p)
	if _, err := a.udp.WriteToUDP(pkt, a.relay); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (a *socksUDPAssociation) Read(p []byte) (int, error) {
	for {
		n, _, err := a.udp.ReadFromUDP(a.buf)
		if err != nil {
			return 0, err
		}
		if n < 4 || a.buf[2] != 0 {
			continue // too short, or a fragmented datagram we do not reassemble
		}
		alen, ok := socksAddrLen(a.buf[3:n])
		if !ok || 3+alen >= n {
			continue
		}
		return copy(p, a.buf[3+alen:n]), nil
	}
}

func (a *socksUDPAssociation) Close() error {
	var err error
	a.closeOnce.Do(func() {
		close(a.closed)
		_ = a.ctrl.Close()
		err = a.udp.Close()
	})
	return err
}

// ---- WireGuard bind --------------------------------------------------------

// proxyBind is the WireGuard device's conn.Bind when the transport must run
// through a SOCKS5 upstream. The device has one peer, so the bind owns a single
// UDP association to it, mirroring netstackBind's single-socket approach.
type proxyBind struct {
	up     *upstream
	target netip.AddrPort

	mu    sync.Mutex
	assoc *socksUDPAssociation
}

func newProxyBind(up *upstream, target netip.AddrPort) *proxyBind {
	return &proxyBind{up: up, target: target}
}

func (b *proxyBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	a, err := b.up.dialSocksUDP(b.target)
	if err != nil {
		return nil, 0, err
	}
	b.mu.Lock()
	b.assoc = a
	b.mu.Unlock()
	ep := nestEndpoint(b.target)
	recv := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := a.Read(bufs[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = ep
		return 1, nil
	}
	return []conn.ReceiveFunc{recv}, port, nil
}

func (b *proxyBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	b.mu.Lock()
	a := b.assoc
	b.mu.Unlock()
	if a == nil {
		return net.ErrClosed
	}
	for _, buf := range bufs {
		if _, err := a.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

func (b *proxyBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.assoc == nil {
		return nil
	}
	err := b.assoc.Close()
	b.assoc = nil
	return err
}

func (b *proxyBind) SetMark(uint32) error { return nil }

func (b *proxyBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return nestEndpoint(ap), nil
}

func (b *proxyBind) BatchSize() int { return 1 }
