//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// Adapted from identity/password/postgres's bounded COMMIT transport fixture.
// Only the disposable loopback connection is intercepted. SQL, transaction
// owners and recovery remain real. The final native record marks staged rehash
// and session effects; earlier reservation transactions must not be faulted.
type enrollmentCommitFault struct {
	before bool
	marker string // Optional final-effect marker for other native workflows.
	cancel context.CancelFunc
	hit    atomic.Bool
}

func TestEnrollmentFaultReaderPreservesPartialFrame(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline := time.Now().Add(time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = server.Write([]byte{'Z', 0, 0})
		_ = server.Close()
	}()
	defer func() { <-done }()
	c := &enrollmentCommitConn{Conn: client, fault: &enrollmentCommitFault{before: true}}
	var output [8]byte
	n, _ := c.Read(output[:])
	if n != 3 || !bytes.Equal(output[:n], []byte{'Z', 0, 0}) {
		t.Fatal("fault reader discarded bytes before a fragmented-frame interruption")
	}
}

func (f *enrollmentCommitFault) dial(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &enrollmentCommitConn{Conn: c, fault: f}, nil
}

type enrollmentCommitConn struct {
	net.Conn
	fault    *enrollmentCommitFault
	mutation atomic.Bool
	pending  []byte // Sole pgx backend-message reader owns this buffer.
}

func (c *enrollmentCommitConn) Write(p []byte) (int, error) {
	// A rolled-back mutation must not fault a later reservation or failure-
	// audit transaction when pgx reuses this physical connection.
	if len(p) >= 5 && p[0] == 'Q' && bytes.EqualFold(p[5:], []byte("rollback\x00")) {
		c.mutation.Store(false)
	}
	marker := c.fault.marker
	if marker == "" {
		marker = "identity_passkey.credentials("
	}
	if bytes.Contains(p, []byte(marker)) {
		c.mutation.Store(true)
		if c.fault.cancel != nil && c.fault.hit.CompareAndSwap(false, true) {
			c.fault.cancel()
		}
	}
	if c.fault.cancel == nil && c.fault.before && c.mutation.Load() && len(p) >= 5 && p[0] == 'Q' && bytes.EqualFold(p[5:], []byte("commit\x00")) && c.fault.hit.CompareAndSwap(false, true) {
		_ = c.Conn.Close()
		return 0, io.ErrUnexpectedEOF
	}
	return c.Conn.Write(p)
}

func (c *enrollmentCommitConn) Read(p []byte) (int, error) {
	// Observe frames without changing the driver's read/deadline semantics.
	// ReadFull used to lose already-read bytes on a partial-frame interruption.
	n, err := c.Conn.Read(p)
	if len(c.pending)+n > (16<<20)+5 {
		return 0, io.ErrUnexpectedEOF
	}
	c.pending = append(c.pending, p[:n]...)
	for len(c.pending) >= 5 {
		size := binary.BigEndian.Uint32(c.pending[1:5])
		if size < 4 || size > 16<<20 {
			return 0, io.ErrUnexpectedEOF
		}
		if len(c.pending) < int(size)+1 {
			break
		}
		message := c.pending[:int(size)+1]
		if c.fault.cancel == nil && !c.fault.before && message[0] == 'C' && bytes.Equal(message[5:], []byte("COMMIT\x00")) && c.mutation.Load() && c.fault.hit.CompareAndSwap(false, true) {
			_ = c.Conn.Close()
			return 0, io.ErrUnexpectedEOF
		}
		if message[0] == 'Z' && len(message) == 6 && message[5] == 'I' {
			c.mutation.Store(false)
		}
		c.pending = c.pending[len(message):]
	}
	return n, err
}
