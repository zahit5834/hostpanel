// Package pubdns asks public recursive resolvers directly, the way the
// outside world (Let's Encrypt, other mail servers) sees a name. The system
// resolver answers from /etc/hosts first, and Ubuntu maps the machine's own
// hostname to 127.0.1.1 there — a server named after its mail host would
// look "not pointing here" to every check that trusts it.
//
// Only A and PTR queries over UDP; no EDNS, no DNSSEC validation (the result
// is a pre-check, never a security decision).
package pubdns

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// DefaultServers are well-known anycast resolvers (Cloudflare, Google, Quad9).
var DefaultServers = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}

// Resolver queries Servers in order until one answers.
type Resolver struct {
	Servers []string
	Timeout time.Duration // per server
}

// Default is the resolver used by the panel.
var Default = &Resolver{Servers: DefaultServers, Timeout: 3 * time.Second}

// ErrNotFound means the name (or the record type) does not exist.
var ErrNotFound = errors.New("kayıt yok")

const (
	typeA   = 1
	typePTR = 12
	classIN = 1
)

// LookupA returns the IPv4 addresses of host (CNAMEs are followed by the
// recursive resolver).
func (r *Resolver) LookupA(ctx context.Context, host string) ([]netip.Addr, error) {
	rrs, err := r.query(ctx, host, typeA)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, rr := range rrs {
		if len(rr.data) == 4 {
			out = append(out, netip.AddrFrom4([4]byte(rr.data)))
		}
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

// LookupPTR returns the reverse names of an IPv4 address.
func (r *Resolver) LookupPTR(ctx context.Context, ip netip.Addr) ([]string, error) {
	ip = ip.Unmap()
	if !ip.Is4() {
		return nil, fmt.Errorf("yalnızca IPv4: %s", ip)
	}
	b := ip.As4()
	rrs, err := r.query(ctx, fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0]), typePTR)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range rrs {
		if rr.name != "" {
			out = append(out, rr.name)
		}
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

type rr struct {
	data []byte // A
	name string // PTR target
}

func (r *Resolver) query(ctx context.Context, name string, qtype uint16) ([]rr, error) {
	q, id, err := buildQuery(name, qtype)
	if err != nil {
		return nil, err
	}
	var errs []string
	for _, srv := range r.Servers {
		rrs, err := r.ask(ctx, srv, q, id, qtype)
		if err == nil || errors.Is(err, ErrNotFound) {
			return rrs, err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		errs = append(errs, srv+": "+err.Error())
	}
	return nil, fmt.Errorf("genel DNS sunucularına ulaşılamadı (%s)", strings.Join(errs, "; "))
}

func (r *Resolver) ask(ctx context.Context, srv string, q []byte, id uint16, qtype uint16) ([]rr, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", srv) // connected socket: only srv's replies arrive
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	if _, err := conn.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		rrs, err := parse(buf[:n], id, qtype)
		if errors.Is(err, errOtherID) {
			continue // stray or late datagram
		}
		return rrs, err
	}
}

func buildQuery(name string, qtype uint16) ([]byte, uint16, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return nil, 0, fmt.Errorf("geçersiz ad %q", name)
	}
	var idb [2]byte
	rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	msg := make([]byte, 12, 12+len(name)+6)
	binary.BigEndian.PutUint16(msg[0:], id)
	binary.BigEndian.PutUint16(msg[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(msg[4:], 1)      // QDCOUNT
	for _, l := range strings.Split(name, ".") {
		if l == "" || len(l) > 63 {
			return nil, 0, fmt.Errorf("geçersiz ad %q", name)
		}
		msg = append(msg, byte(len(l)))
		msg = append(msg, l...)
	}
	msg = append(msg, 0, byte(qtype>>8), byte(qtype), 0, classIN)
	return msg, id, nil
}

var (
	errOtherID = errors.New("other id")
	errShort   = errors.New("kısa/bozuk yanıt")
)

func parse(msg []byte, id uint16, qtype uint16) ([]rr, error) {
	if len(msg) < 12 {
		return nil, errShort
	}
	if binary.BigEndian.Uint16(msg[0:]) != id {
		return nil, errOtherID
	}
	flags := binary.BigEndian.Uint16(msg[2:])
	if flags&0x8000 == 0 {
		return nil, errShort
	}
	switch rcode := flags & 0xF; rcode {
	case 0:
	case 3: // NXDOMAIN
		return nil, ErrNotFound
	default:
		return nil, fmt.Errorf("yanıt kodu %d", rcode)
	}
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	an := int(binary.BigEndian.Uint16(msg[6:]))
	off := 12
	var err error
	for i := 0; i < qd; i++ {
		if _, off, err = readName(msg, off); err != nil {
			return nil, err
		}
		off += 4
	}
	var out []rr
	for i := 0; i < an; i++ {
		if _, off, err = readName(msg, off); err != nil {
			return nil, err
		}
		if off+10 > len(msg) {
			return nil, errShort
		}
		typ := binary.BigEndian.Uint16(msg[off:])
		class := binary.BigEndian.Uint16(msg[off+2:])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8:]))
		off += 10
		if off+rdlen > len(msg) {
			return nil, errShort
		}
		if class == classIN && typ == qtype {
			switch typ {
			case typeA:
				out = append(out, rr{data: msg[off : off+rdlen]})
			case typePTR:
				n, _, err := readName(msg, off)
				if err != nil {
					return nil, err
				}
				out = append(out, rr{name: n})
			}
		}
		off += rdlen
	}
	if len(out) == 0 {
		return nil, ErrNotFound // NOERROR without data (NODATA)
	}
	return out, nil
}

// readName decodes a (possibly compressed) name at off and returns the
// offset after it in the original position.
func readName(msg []byte, off int) (string, int, error) {
	var labels []string
	next := -1
	for jumps := 0; ; {
		if off >= len(msg) {
			return "", 0, errShort
		}
		l := int(msg[off])
		switch {
		case l == 0:
			if next < 0 {
				next = off + 1
			}
			return strings.Join(labels, "."), next, nil
		case l&0xC0 == 0xC0:
			if off+1 >= len(msg) || jumps > 32 {
				return "", 0, errShort
			}
			if next < 0 {
				next = off + 2
			}
			off = int(binary.BigEndian.Uint16(msg[off:]) & 0x3FFF)
			jumps++
		case l&0xC0 != 0:
			return "", 0, errShort
		default:
			if off+1+l > len(msg) {
				return "", 0, errShort
			}
			labels = append(labels, string(msg[off+1:off+1+l]))
			off += 1 + l
		}
	}
}
