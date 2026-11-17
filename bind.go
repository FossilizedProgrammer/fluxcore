package main

import (
	"net"
	"net/netip"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

// netstackBind is the inner device's conn.Bind for multi-hop: instead of a real
// UDP socket it dials the exit gateway on the OUTER device's netstack, so every
// datagram the inner tunnel sends is routed through the entry tunnel. The inner
// device has exactly one peer, so one connected UDP socket is enough.
//
// This mirrors clients/native/wgnest/bind.go in the upstream repository.
type netstackBind struct {
	outer *netstack.Net
	exit  netip.AddrPort

	mu   sync.Mutex
	conn net.Conn
}

func newNetstackBind(outer *netstack.Net, exit netip.AddrPort) *netstackBind {
	return &netstackBind{outer: outer, exit: exit}
}

func (b *netstackBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	c, err := b.outer.DialUDPAddrPort(netip.AddrPort{}, b.exit)
	if err != nil {
		return nil, 0, err
	}
	b.conn = c
	ep := nestEndpoint(b.exit)
	recv := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := c.Read(bufs[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = ep
		return 1, nil
	}
	return []conn.ReceiveFunc{recv}, port, nil
}

func (b *netstackBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	b.mu.Lock()
	c := b.conn
	b.mu.Unlock()
	if c == nil {
		return net.ErrClosed
	}
	for _, buf := range bufs {
		if _, err := c.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

func (b *netstackBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn == nil {
		return nil
	}
	err := b.conn.Close()
	b.conn = nil
	return err
}

func (b *netstackBind) SetMark(uint32) error { return nil }

func (b *netstackBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return nestEndpoint(ap), nil
}

func (b *netstackBind) BatchSize() int { return 1 }

type nestEndpoint netip.AddrPort

func (e nestEndpoint) ClearSrc()           {}
func (e nestEndpoint) SrcToString() string { return "" }
func (e nestEndpoint) DstToString() string { return netip.AddrPort(e).String() }
func (e nestEndpoint) DstToBytes() []byte  { b, _ := netip.AddrPort(e).MarshalBinary(); return b }
func (e nestEndpoint) DstIP() netip.Addr   { return netip.AddrPort(e).Addr() }
func (e nestEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
