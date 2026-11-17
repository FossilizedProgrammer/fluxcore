package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// tlsBridge is the client half of the wg-tls transport: a loopback UDP socket
// the WireGuard device dials as its peer endpoint, carrying length-prefixed
// datagrams (2-byte big-endian) over one TLS connection to the gateway relay.
//
// The TLS certificate is deliberately NOT verified: this layer is camouflage,
// and trust is anchored in the inner WireGuard handshake. Do not describe it as
// additional transport security.
type tlsBridge struct {
	tlsConn net.Conn
	udp     *net.UDPConn
	srcCh   chan *net.UDPAddr

	closeOnce sync.Once
	closed    chan struct{}
	errMu     sync.Mutex
	lastErr   error
}

func dialTLSBridge(ctx context.Context, serverAddr, sni string) (*tlsBridge, error) {
	dialer := &net.Dialer{Timeout: 12 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(raw, &tls.Config{
		// #nosec G402 -- camouflage only; the inner WireGuard handshake is what
		// authenticates the gateway.
		InsecureSkipVerify: true,
		ServerName:         sni,
		MinVersion:         tls.VersionTLS12,
	})
	hsCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("wg-tls handshake: %w", err)
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	b := &tlsBridge{
		tlsConn: tlsConn,
		udp:     udp,
		srcCh:   make(chan *net.UDPAddr, 1),
		closed:  make(chan struct{}),
	}
	go b.udpToTLS()
	go b.tlsToUDP()
	return b, nil
}

func (b *tlsBridge) localEndpoint() string { return b.udp.LocalAddr().String() }

func (b *tlsBridge) setErr(err error) {
	b.errMu.Lock()
	if b.lastErr == nil {
		b.lastErr = err
	}
	b.errMu.Unlock()
}

// Err reports why the bridge died, if it did.
func (b *tlsBridge) Err() error {
	b.errMu.Lock()
	defer b.errMu.Unlock()
	return b.lastErr
}

func (b *tlsBridge) Close() error {
	var err error
	b.closeOnce.Do(func() {
		close(b.closed)
		_ = b.tlsConn.Close()
		err = b.udp.Close()
	})
	return err
}

func writeDatagramFrame(w io.Writer, pkt []byte) error {
	if len(pkt) > 65535 {
		return fmt.Errorf("wg-tls: datagram too large (%d bytes)", len(pkt))
	}
	buf := make([]byte, 2+len(pkt))
	binary.BigEndian.PutUint16(buf, uint16(len(pkt)))
	copy(buf[2:], pkt)
	// One Write per datagram: one TLS record, mirroring the gateway relay.
	_, err := w.Write(buf)
	return err
}

func readDatagramFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	pkt := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(r, pkt); err != nil {
		return nil, err
	}
	return pkt, nil
}

func (b *tlsBridge) udpToTLS() {
	buf := make([]byte, 65535)
	for {
		n, src, err := b.udp.ReadFromUDP(buf)
		if err != nil {
			b.setErr(err)
			_ = b.Close()
			return
		}
		select {
		case b.srcCh <- src:
		default:
			select {
			case <-b.srcCh:
			default:
			}
			b.srcCh <- src
		}
		if err := writeDatagramFrame(b.tlsConn, buf[:n]); err != nil {
			b.setErr(err)
			_ = b.Close()
			return
		}
	}
}

func (b *tlsBridge) tlsToUDP() {
	var dst *net.UDPAddr
	for {
		pkt, err := readDatagramFrame(b.tlsConn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				b.setErr(err)
			}
			_ = b.Close()
			return
		}
		select {
		case dst = <-b.srcCh:
		default:
		}
		if dst == nil {
			continue // no datagram from the device yet; nowhere to deliver
		}
		if _, err := b.udp.WriteToUDP(pkt, dst); err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
		}
	}
}
