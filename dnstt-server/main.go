// dnstt-server is the server end of a DNS tunnel.
//
// Usage:
//
//	dnstt-server -gen-key [-privkey-file PRIVKEYFILE] [-pubkey-file PUBKEYFILE]
//	TOR_PT_MANAGED_TRANSPORT_VER=1 TOR_PT_SERVER_TRANSPORTS=dnstt TOR_PT_SERVER_BINDADDR=dnstt-ADDR TOR_PT_ORPORT=UPSTREAMADDR dnstt-server [-privkey PRIVKEY|-privkey-file PRIVKEYFILE] DOMAIN
//
// Example:
//
//	dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub
//	TOR_PT_MANAGED_TRANSPORT_VER=1 TOR_PT_SERVER_TRANSPORTS=dnstt TOR_PT_SERVER_BINDADDR=dnstt-127.0.0.1:53 TOR_PT_ORPORT=127.0.0.1:8000 dnstt-server -privkey-file server.key t.example.com
//
// To generate a persistent server private key, first run with the -gen-key
// option. By default the generated private and public keys are printed to
// standard output. To save them to files instead, use the -privkey-file and
// -pubkey-file options.
//
//	dnstt-server -gen-key
//	dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub
//
// You can give the server's private key as a file or as a hex string.
//
//	-privkey-file server.key
//	-privkey 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
//
// The -udp option controls the address that will listen for incoming DNS
// queries.
//
// The -mtu option controls the maximum size of response UDP payloads.
// Queries that do not advertise requester support for responses of at least
// this size at least this size will be responded to with a FORMERR. The default
// value is maxUDPPayload.
//
// DOMAIN is the root of the DNS zone reserved for the tunnel. See README for
// instructions on setting it up.
//
// UPSTREAMADDR is the TCP address to which incoming tunnelled streams will be
// forwarded.
// Example static records config file (replace example.com with your own FQDN)
// Note the TRAILING DOT for the NS record. It has to have TRAILING DOT.
/* /etc/dnstt/static_records.json
[
  {
    "pattern": "example.com",
    "type": "A",
    "value": "1.2.3.4"
  },
  {
    "pattern": "*.example.com",
    "type": "AAAA",
    "value": "2001:db8::1"
  },
  {
    "pattern": "example.com",
    "type": "NS",
    "value": "n.example.com."
  },
  {
    "pattern": "info.example.com",
    "type": "TXT",
    "value": "Hello World"
  }
]
*/
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	ptMethodName = "dnstt"

	// smux streams will be closed after this much time without receiving data.
	idleTimeout = 2 * time.Minute

	// How to set the TTL field in Answer resource records.
	responseTTL = 60

	// How long we may wait for downstream data before sending an empty
	// response. If another query comes in while we are waiting, we'll send
	// an empty response anyway and restart the delay timer for the next
	// response.
	//
	// This number should be less than 2 seconds, which in 2019 was reported
	// to be the query timeout of the Quad9 DoH server.
	// https://dnsencryption.info/imc19-doe.html Section 4.2, Finding 2.4
	maxResponseDelay = 1 * time.Second

	// How long to wait for a TCP connection to upstream to be established.
	upstreamDialTimeout = 30 * time.Second
)

type ConfigEntry struct {
	Pattern string `json:"pattern"` // e.g. "abcd.com" or "*.abcd.com"
	Type    string `json:"type"`    // "A" or "TXT"
	Value   string `json:"value"`   // "1.2.3.4" or "hello world"
}

var (
	// We don't send UDP payloads larger than this, in an attempt to avoid
	// network-layer fragmentation. 1280 is the minimum IPv6 MTU, 40 bytes
	// is the size of an IPv6 header (though without any extension headers),
	// and 8 bytes is the size of a UDP header.
	//
	// Control this value with the -mtu command-line option.
	//
	// https://dnsflagday.net/2020/#message-size-considerations
	// "An EDNS buffer size of 1232 bytes will avoid fragmentation on nearly
	// all current networks."
	//
	// On 2020-04-19, the Quad9 resolver was seen to have a UDP payload size
	// of 1232. Cloudflare's was 1452, and Google's was 4096.
	maxUDPPayload   = 1280 - 40 - 8
	staticRecords   []ConfigEntry
	staticRecordsMu sync.RWMutex
)

func loadConfig(filename string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // It's okay if config doesn't exist
		}
		return err
	}
	var newRecords []ConfigEntry
	if err := json.Unmarshal(data, &newRecords); err != nil {
		return err
	}
	staticRecordsMu.Lock()
	staticRecords = newRecords
	staticRecordsMu.Unlock()

	return nil
}
func generateRandomIPInSubnet(cidrStr string) net.IP {
	ip, ipnet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return net.ParseIP(cidrStr) // Fallback to single IP if not a CIDR string
	}

	isIPv4 := ip.To4() != nil

	if isIPv4 {
		ip4 := ip.To4()
		mask := ipnet.Mask
		if len(mask) == 16 { // Ensure 4-byte mask
			mask = mask[12:]
		}
		randomIP := make(net.IP, 4)
		attempts := 0
		for attempts < 10 { // Max attempts to prevent infinite loops on tiny subnets (/31, /32)
			attempts++
			_, _ = rand.Read(randomIP)
			for i := 0; i < 4; i++ {
				// Combine network bits with randomized host bits
				randomIP[i] = (ip4[i] & mask[i]) | (randomIP[i] & ^mask[i])
			}
			lastOctet := randomIP[3]
			// Constraint: Avoid last octet 0, 1, and 255
			if lastOctet != 0 && lastOctet != 1 && lastOctet != 255 {
				return randomIP
			}
		}
		return ip4 // Fallback if it couldn't find a valid IP in 10 tries
	} else {
		// IPv6 logic
		ip16 := ip.To16()
		mask := ipnet.Mask
		randomIP := make(net.IP, 16)
		_, _ = rand.Read(randomIP)
		for i := 0; i < 16; i++ {
			randomIP[i] = (ip16[i] & mask[i]) | (randomIP[i] & ^mask[i])
		}
		return randomIP
	}
}

// domainToString converts the [][]byte representation of a name to a string.
func domainToString(name dns.Name) string {
	var sb strings.Builder
	for i, label := range name {
		if i > 0 {
			sb.WriteByte('.')
		}
		sb.Write(label)
	}
	return sb.String()
}

// matchDomain checks if a domain matches a pattern (supports simple *.suffix).
func matchDomain(pattern, domain string) bool {
	pattern = strings.ToLower(pattern)
	domain = strings.ToLower(domain)

	if pattern == domain {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // e.g. ".abcd.com"
		if strings.HasSuffix(domain, suffix) {
			// Ensure we don't match "fake.abcd.com" against "*.bcd.com" logic blindly,
			// though standard DNS wildcard logic is complex, this suffices for "*.abcd.com".
			return true
		}
	}
	return false
}

/*
https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2

RECORD TYPE     value and meaning

A               1 a host address
NS              2 an authoritative name server
MD              3 a mail destination (Obsolete - use MX)
MF              4 a mail forwarder (Obsolete - use MX)
CNAME           5 the canonical name for an alias
SOA             6 marks the start of a zone of authority
MB              7 a mailbox domain name (EXPERIMENTAL)
MG              8 a mail group member (EXPERIMENTAL)
MR              9 a mail rename domain name (EXPERIMENTAL)
NULL            10 a null RR (EXPERIMENTAL)
WKS             11 a well known service description
PTR             12 a domain name pointer
HINFO           13 host information
MINFO           14 mailbox or mail list information
MX              15 mail exchange
TXT             16 text strings

*/

// staticResponseFor checks if the query matches a static config entry.
func staticResponseFor(query *dns.Message) *dns.Message {
	const RECTypeA = 1
	const RECTypeNS = 2
	const RECTypeTXT = 16
	const RECTypeAAAA = 28

	if query.Flags&0x8000 != 0 {
		return nil // Not a query
	}
	if len(query.Question) != 1 {
		return nil
	}

	q := query.Question[0]
	// Convert query name to lowercase string for case-insensitive matching
	qName := strings.ToLower(domainToString(q.Name))

	var matchedEntry ConfigEntry
	var found bool

	staticRecordsMu.RLock()
	for i := range staticRecords {
		rec := &staticRecords[i]

		// Filter by Record Type
		switch q.Type {
		case RECTypeA:
			if rec.Type != "A" {
				continue
			}
		case RECTypeNS:
			if rec.Type != "NS" {
				continue
			}
		case RECTypeTXT:
			if rec.Type != "TXT" {
				continue
			}
		case RECTypeAAAA:
			if rec.Type != "AAAA" {
				continue
			}
		default:
			continue // Skip unsupported query types
		}

		if matchDomain(rec.Pattern, qName) {
			matchedEntry = *rec
			found = true
			break
		}
	}
	staticRecordsMu.RUnlock()

	if !found {
		return nil
	}

	// Build Response
	resp := &dns.Message{
		ID:       query.ID,
		Flags:    0x8400, // QR=1, AA=1, RCODE=0
		Question: query.Question,
	}

	// Create Answer RR
	rr := dns.RR{
		Name:  q.Name,
		Type:  q.Type,
		Class: q.Class,
		TTL:   300,
	}

	switch matchedEntry.Type {
	case "A":
		//ip := net.ParseIP(matchedEntry.Value)
		ip := generateRandomIPInSubnet(matchedEntry.Value)
		if ip4 := ip.To4(); ip4 != nil {
			rr.Data = ip4
		} else {
			log.Printf("Invalid IPv4 in config for %s: %s", matchedEntry.Pattern, matchedEntry.Value)
			return nil
		}
	case "NS":
		encoded, err := dns.EncodeDomainName(matchedEntry.Value)
		if err != nil {
			log.Printf("Invalid NS domain for %s: %s", matchedEntry.Pattern, matchedEntry.Value)
			return nil
		}
		rr.Data = encoded
	case "AAAA":
		//ip := net.ParseIP(matchedEntry.Value)
		ip := generateRandomIPInSubnet(matchedEntry.Value)
		if ip16 := ip.To16(); ip16 != nil {
			rr.Data = ip16
		} else {
			log.Printf("Invalid IPv6 in config for %s: %s", matchedEntry.Pattern, matchedEntry.Value)
			return nil
		}
	case "TXT":
		rr.Data = dns.EncodeRDataTXT([]byte(matchedEntry.Value))
	}

	resp.Answer = append(resp.Answer, rr)
	return resp
}

func startAPI(addr string, configPath string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/records", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			staticRecordsMu.RLock()
			data, err := json.Marshal(staticRecords)
			staticRecordsMu.RUnlock()

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(data)

		} else if r.Method == http.MethodPost {
			var newRecords []ConfigEntry
			if err := json.NewDecoder(r.Body).Decode(&newRecords); err != nil {
				http.Error(w, "Invalid JSON body: "+err.Error(), http.StatusBadRequest)
				return
			}

			// Replace the records
			staticRecordsMu.Lock()
			staticRecords = newRecords
			staticRecordsMu.Unlock()

			if configPath != "" {
				if len(newRecords) > 0 && newRecords[0].Type == "SAVE_TO_FS" {
					data, _ := json.MarshalIndent(newRecords, "", "  ")
					_ = ioutil.WriteFile(configPath, data, 0644)
				}
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "success"}`))
		} else {
			http.Error(w, "Method not allowed. Use GET or POST", http.StatusMethodNotAllowed)
		}
	})

	log.Printf("Starting API server on %s", addr)
	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Printf("API server error: %v", err)
		}
	}()
}

// base32Encoding is a base32 encoding without padding.
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// generateKeypair generates a private key and the corresponding public key. If
// privkeyFilename and pubkeyFilename are respectively empty, it prints the
// corresponding key to standard output; otherwise it saves the key to the given
// file name. The private key is saved with mode 0400 and the public key is
// saved with 0666 (before umask). In case of any error, it attempts to delete
// any files it has created before returning.
func generateKeypair(privkeyFilename, pubkeyFilename string) (err error) {
	// Filenames to delete in case of error (avoid leaving partially written
	// files).
	var toDelete []string
	defer func() {
		for _, filename := range toDelete {
			log.Printf("deleting partially written file %s\n", filename)
			if closeErr := os.Remove(filename); closeErr != nil {
				log.Printf("cannot remove %s: %v\n", filename, closeErr)
				if err == nil {
					err = closeErr
				}
			}
		}
	}()

	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		return err
	}
	pubkey := noise.PubkeyFromPrivkey(privkey)

	if privkeyFilename != "" {
		// Save the privkey to a file.
		f, err := os.OpenFile(privkeyFilename, os.O_RDWR|os.O_CREATE, 0400)
		if err != nil {
			return err
		}
		toDelete = append(toDelete, privkeyFilename)
		err = noise.WriteKey(f, privkey)
		if err2 := f.Close(); err == nil {
			err = err2
		}
		if err != nil {
			return err
		}
	}

	if pubkeyFilename != "" {
		// Save the pubkey to a file.
		f, err := os.Create(pubkeyFilename)
		if err != nil {
			return err
		}
		toDelete = append(toDelete, pubkeyFilename)
		err = noise.WriteKey(f, pubkey)
		if err2 := f.Close(); err == nil {
			err = err2
		}
		if err != nil {
			return err
		}
	}

	// All good, allow the written files to remain.
	toDelete = nil

	if privkeyFilename != "" {
		fmt.Printf("privkey written to %s\n", privkeyFilename)
	} else {
		fmt.Printf("privkey %x\n", privkey)
	}
	if pubkeyFilename != "" {
		fmt.Printf("pubkey  written to %s\n", pubkeyFilename)
	} else {
		fmt.Printf("pubkey  %x\n", pubkey)
	}

	return nil
}

// readKeyFromFile reads a key from a named file.
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()
	return noise.ReadKey(f)
}

// handleStream bidirectionally connects a client stream with a TCP socket
// addressed by upstream.
func handleStream(stream *smux.Stream, upstream string, conv uint32) error {
	dialer := net.Dialer{
		Timeout: upstreamDialTimeout,
	}
	upstreamConn, err := dialer.Dial("tcp", upstream)
	if err != nil {
		return fmt.Errorf("stream %08x:%d connect upstream: %v", conv, stream.ID(), err)
	}
	defer func() {
		_ = upstreamConn.Close()
	}()
	upstreamTCPConn := upstreamConn.(*net.TCPConn)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, upstreamTCPConn)
		if err == io.EOF {
			// smux Stream.Write may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy stream←upstream: %v", conv, stream.ID(), err)
		}
		_ = upstreamTCPConn.CloseRead()
		_ = stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(upstreamTCPConn, stream)
		if err == io.EOF {
			// smux Stream.WriteTo may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy upstream←stream: %v", conv, stream.ID(), err)
		}
		_ = upstreamTCPConn.CloseWrite()
	}()
	wg.Wait()

	return nil
}

// acceptStreams wraps a KCP session in a Noise channel and an smux.Session,
// then awaits smux streams. It passes each stream to handleStream.
func acceptStreams(conn *kcp.UDPSession, privkey []byte, upstream string) error {
	// Put a Noise channel on top of the KCP conn.
	rw, err := noise.NewServer(conn, privkey)
	if err != nil {
		return err
	}

	// Put an smux session on top of the encrypted Noise channel.
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024 // default is 65536
	sess, err := smux.Server(rw, smuxConfig)
	if err != nil {
		return err
	}
	defer func() {
		_ = sess.Close()
	}()

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			//goland:noinspection GoDeprecation
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		log.Printf("begin stream %08x:%d", conn.GetConv(), stream.ID())
		go func() {
			defer func() {
				log.Printf("end stream %08x:%d", conn.GetConv(), stream.ID())
				_ = stream.Close()
			}()
			err := handleStream(stream, upstream, conn.GetConv())
			if err != nil {
				log.Printf("stream %08x:%d handleStream: %v", conn.GetConv(), stream.ID(), err)
			}
		}()
	}
}

// acceptSessions listens for incoming KCP connections and passes them to
// acceptStreams.
func acceptSessions(ln *kcp.Listener, privkey []byte, mtu int, upstream string) error {
	for {
		conn, err := ln.AcceptKCP()
		if err != nil {
			//goland:noinspection GoDeprecation
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		log.Printf("begin session %08x", conn.GetConv())
		// Permit coalescing the payloads of consecutive sends.
		conn.SetStreamMode(true)
		// Disable the dynamic congestion window (limit only by the
		// maximum of local and remote static windows).
		conn.SetNoDelay(
			0, // default nodelay
			0, // default interval
			0, // default resend
			1, // nc=1 => congestion window off
		)
		conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
		if rc := conn.SetMtu(mtu); !rc {
			panic(rc)
		}
		go func() {
			defer func() {
				log.Printf("end session %08x", conn.GetConv())
				_ = conn.Close()
			}()
			err := acceptStreams(conn, privkey, upstream)
			if err != nil && !errors.Is(err, io.ErrClosedPipe) {
				log.Printf("session %08x acceptStreams: %v", conn.GetConv(), err)
			}
		}()
	}
}

// nextPacket reads the next length-prefixed packet from r, ignoring padding. It
// returns a nil error only when a packet was read successfully. It returns
// io.EOF only when there were 0 bytes remaining to read from r. It returns
// io.ErrUnexpectedEOF when EOF occurs in the middle of an encoded packet.
//
// The prefixing scheme is as follows. A length prefix L < 0xe0 means a data
// packet of L bytes. A length prefix L >= 0xe0 means padding of L - 0xe0 bytes
// (not counting the length of the length prefix itself).
func nextPacket(r *bytes.Reader) ([]byte, error) {
	// Convert io.EOF to io.ErrUnexpectedEOF.
	eof := func(err error) error {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}

	for {
		prefix, err := r.ReadByte()
		if err != nil {
			// We may return a real io.EOF only here.
			return nil, err
		}
		if prefix >= 224 {
			paddingLen := prefix - 224
			_, err := io.CopyN(ioutil.Discard, r, int64(paddingLen))
			if err != nil {
				return nil, eof(err)
			}
		} else {
			p := make([]byte, int(prefix))
			_, err = io.ReadFull(r, p)
			return p, eof(err)
		}
	}
}

// responseFor constructs a response dns.Message that is appropriate for query.
// Along with the dns.Message, it returns the query's decoded data payload. If
// the returned dns.Message is nil, it means that there should be no response to
// this query. If the returned dns.Message has an Rcode() of dns.RcodeNoError,
// the message is a candidate for for carrying downstream data in a TXT record.
func responseFor(query *dns.Message, domain dns.Name) (*dns.Message, []byte) {
	resp := &dns.Message{
		ID:       query.ID,
		Flags:    0x8000, // QR = 1, RCODE = no error
		Question: query.Question,
	}

	if query.Flags&0x8000 != 0 {
		// QR != 0, this is not a query. Don't even send a response.
		return nil, nil
	}

	// Check for EDNS(0) support. Include our own OPT RR only if we receive
	// one from the requester.
	// https://tools.ietf.org/html/rfc6891#section-6.1.1
	// "Lack of presence of an OPT record in a request MUST be taken as an
	// indication that the requester does not implement any part of this
	// specification and that the responder MUST NOT include an OPT record
	// in its response."
	payloadSize := 0
	for _, rr := range query.Additional {
		if rr.Type != dns.RRTypeOPT {
			continue
		}
		if len(resp.Additional) != 0 {
			// https://tools.ietf.org/html/rfc6891#section-6.1.1
			// "If a query message with more than one OPT RR is
			// received, a FORMERR (RCODE=1) MUST be returned."
			resp.Flags |= dns.RcodeFormatError
			log.Printf("FORMERR: more than one OPT RR")
			return resp, nil
		}
		resp.Additional = append(resp.Additional, dns.RR{
			Name:  dns.Name{},
			Type:  dns.RRTypeOPT,
			Class: 4096, // responder's UDP payload size
			TTL:   0,
			Data:  []byte{},
		})
		additional := &resp.Additional[0]

		version := (rr.TTL >> 16) & 0xff
		if version != 0 {
			// https://tools.ietf.org/html/rfc6891#section-6.1.1
			// "If a responder does not implement the VERSION level
			// of the request, then it MUST respond with
			// RCODE=BADVERS."
			resp.Flags |= dns.ExtendedRcodeBadVers & 0xf
			additional.TTL = (dns.ExtendedRcodeBadVers >> 4) << 24
			log.Printf("BADVERS: EDNS version %d != 0", version)
			return resp, nil
		}

		payloadSize = int(rr.Class)
	}
	if payloadSize < 512 {
		// https://tools.ietf.org/html/rfc6891#section-6.1.1 "Values
		// lower than 512 MUST be treated as equal to 512."
		payloadSize = 512
	}
	// We will return RcodeFormatError if payloadSize is too small, but
	// first, check the name in order to set the AA bit properly.

	// There must be exactly one question.
	if len(query.Question) != 1 {
		resp.Flags |= dns.RcodeFormatError
		log.Printf("FORMERR: too few or too many questions (%d)", len(query.Question))
		return resp, nil
	}
	question := query.Question[0]
	// Check the name to see if it ends in our chosen domain, and extract
	// all that comes before the domain if it does. If it does not, we will
	// return RcodeNameError below, but prefer to return RcodeFormatError
	// for payload size if that applies as well.
	prefix, ok := question.Name.TrimSuffix(domain)
	if !ok {
		// Not a name we are authoritative for.
		resp.Flags |= dns.RcodeNameError
		log.Printf("NXDOMAIN: not authoritative for %s", question.Name)
		return resp, nil
	}
	resp.Flags |= 0x0400 // AA = 1

	if query.Opcode() != 0 {
		// We don't support OPCODE != QUERY.
		resp.Flags |= dns.RcodeNotImplemented
		log.Printf("NOTIMPL: unrecognized OPCODE %d", query.Opcode())
		return resp, nil
	}

	if question.Type != dns.RRTypeTXT {
		// We only support QTYPE == TXT.
		resp.Flags |= dns.RcodeNameError
		// No log message here; it's common for recursive resolvers to
		// send NS or A queries when the client only asked for a TXT. I
		// suspect this is related to QNAME minimization, but I'm not
		// sure. https://tools.ietf.org/html/rfc7816
		// log.Printf("NXDOMAIN: QTYPE %d != TXT", question.Type)
		return resp, nil
	}

	encoded := bytes.ToUpper(bytes.Join(prefix, nil))
	payload := make([]byte, base32Encoding.DecodedLen(len(encoded)))
	n, err := base32Encoding.Decode(payload, encoded)
	if err != nil {
		// Base32 error, make like the name doesn't exist.
		resp.Flags |= dns.RcodeNameError
		log.Printf("NXDOMAIN: base32 decoding: %v", err)
		return resp, nil
	}
	payload = payload[:n]

	// We require clients to support EDNS(0) with a minimum payload size;
	// otherwise we would have to set a small KCP MTU (only around 200
	// bytes). https://tools.ietf.org/html/rfc6891#section-7 "If there is a
	// problem with processing the OPT record itself, such as an option
	// value that is badly formatted or that includes out-of-range values, a
	// FORMERR MUST be returned."
	if payloadSize < maxUDPPayload {
		resp.Flags |= dns.RcodeFormatError
		log.Printf("FORMERR: requester payload size %d is too small (minimum %d)", payloadSize, maxUDPPayload)
		return resp, nil
	}

	return resp, payload
}

// record represents a DNS message appropriate for a response to a previously
// received query, along with metadata necessary for sending the response.
// recvLoop sends instances of record to sendLoop via a channel. sendLoop
// receives instances of record and may fill in the message's Answer section
// before sending it.
type record struct {
	Resp     *dns.Message
	Addr     net.Addr
	ClientID turbotunnel.ClientID
}

// recvLoop repeatedly calls dnsConn.ReadFrom, extracts the packets contained in
// the incoming DNS queries, and puts them on ttConn's incoming queue. Whenever
// a query calls for a response, constructs a partial response and passes it to
// sendLoop over ch.
func recvLoop(domain dns.Name, dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch chan<- *record) error {
	for {
		var buf [4096]byte
		n, addr, err := dnsConn.ReadFrom(buf[:])
		if err != nil {
			//goland:noinspection GoDeprecation
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Printf("ReadFrom temporary error: %v", err)
				continue
			}
			return err
		}
		//log.Printf("Received Query from %v", addr.String())

		// Got a UDP packet. Try to parse it as a DNS message.
		query, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			log.Printf("cannot parse DNS query: %v", err)
			continue
		}

		// Check for static config response first
		if staticMsg := staticResponseFor(&query); staticMsg != nil {
			buf, err := staticMsg.WireFormat()
			if err == nil {
				_, _ = dnsConn.WriteTo(buf, addr)
			} else {
				log.Printf("static response WireFormat error: %v", err)
			}
			continue
		}

		resp, payload := responseFor(&query, domain)
		// Extract the ClientID from the payload.
		var clientID turbotunnel.ClientID
		n = copy(clientID[:], payload)
		payload = payload[n:]
		if n == len(clientID) {
			// Discard padding and pull out the packets contained in
			// the payload.
			r := bytes.NewReader(payload)
			for {
				p, err := nextPacket(r)
				if err != nil {
					break
				}
				// Feed the incoming packet to KCP.
				ttConn.QueueIncoming(p, clientID)
			}
		} else {
			// Payload is not long enough to contain a ClientID.
			if resp != nil && resp.Rcode() == dns.RcodeNoError {
				resp.Flags |= dns.RcodeNameError
				log.Printf("NXDOMAIN: %d bytes are too short to contain a ClientID", n)
			}
		}
		// If a response is called for, pass it to sendLoop via the channel.
		if resp != nil {
			select {
			case ch <- &record{resp, addr, clientID}:
			default:
			}
		}
	}
}

// sendLoop repeatedly receives records from ch. Those that represent an error
// response, it sends on the network immediately. Those that represent a
// response capable of carrying data, it packs full of as many packets as will
// fit while keeping the total size under maxEncodedPayload, then sends it.
func sendLoop(dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch <-chan *record, maxEncodedPayload int) error {
	var nextRec *record
	for {
		rec := nextRec
		nextRec = nil

		if rec == nil {
			var ok bool
			rec, ok = <-ch
			if !ok {
				break
			}
		}

		if rec.Resp.Rcode() == dns.RcodeNoError && len(rec.Resp.Question) == 1 {
			// If it's a non-error response, we can fill the Answer
			// section with downstream packets.

			// Any changes to how responses are built need to happen
			// also in computeMaxEncodedPayload.
			rec.Resp.Answer = []dns.RR{
				{
					Name:  rec.Resp.Question[0].Name,
					Type:  rec.Resp.Question[0].Type,
					Class: rec.Resp.Question[0].Class,
					TTL:   responseTTL,
					Data:  nil, // will be filled in below
				},
			}

			var payload bytes.Buffer
			limit := maxEncodedPayload
			// We loop and bundle as many packets from OutgoingQueue
			// into the response as will fit. Any packet that would
			// overflow the capacity of the DNS response, we stash
			// to be bundled into a future response.
			timer := time.NewTimer(maxResponseDelay)
			for {
				var p []byte
				unstash := ttConn.Unstash(rec.ClientID)
				outgoing := ttConn.OutgoingQueue(rec.ClientID)
				// Prioritize taking a packet first from the
				// stash, then from the outgoing queue, then
				// finally check for the expiration of the timer
				// or for a receive on ch (indicating a new
				// query that we must respond to).
				select {
				case p = <-unstash:
				default:
					select {
					case p = <-unstash:
					case p = <-outgoing:
					default:
						select {
						case p = <-unstash:
						case p = <-outgoing:
						case <-timer.C:
						case nextRec = <-ch:
						}
					}
				}
				// We wait for the first packet in a bundle
				// only. The second and later packets must be
				// immediately available or they will be omitted
				// from this bundle.
				timer.Reset(0)

				if len(p) == 0 {
					// timer expired or receive on ch, we
					// are done with this response.
					break
				}

				limit -= 2 + len(p)
				if payload.Len() == 0 {
					// No packet length check for the first
					// packet; if it's too large, we allow
					// it to be truncated and dropped by the
					// receiver.
				} else if limit < 0 {
					// Stash this packet to send in the next
					// response.
					ttConn.Stash(p, rec.ClientID)
					break
				}
				if int(uint16(len(p))) != len(p) {
					panic(len(p))
				}
				_ = binary.Write(&payload, binary.BigEndian, uint16(len(p)))
				payload.Write(p)
			}
			timer.Stop()

			rec.Resp.Answer[0].Data = dns.EncodeRDataTXT(payload.Bytes())
		}

		buf, err := rec.Resp.WireFormat()
		if err != nil {
			log.Printf("resp WireFormat: %v", err)
			continue
		}
		// Truncate if necessary.
		// https://tools.ietf.org/html/rfc1035#section-4.1.1
		if len(buf) > maxUDPPayload {
			log.Printf("truncating response of %d bytes to max of %d", len(buf), maxUDPPayload)
			buf = buf[:maxUDPPayload]
			buf[2] |= 0x02 // TC = 1
		}

		// Now we actually send the message as a UDP packet.
		_, err = dnsConn.WriteTo(buf, rec.Addr)
		if err != nil {
			//goland:noinspection GoDeprecation
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Printf("WriteTo temporary error: %v", err)
				continue
			}
			return err
		}
	}
	return nil
}

// computeMaxEncodedPayload computes the maximum amount of downstream TXT RR
// data that keep the overall response size less than maxUDPPayload, in the
// worst case when the response answers a query that has a maximum-length name
// in its Question section. Returns 0 in the case that no amount of data makes
// the overall response size small enough.
//
// This function needs to be kept in sync with sendLoop with regard to how it
// builds candidate responses.
func computeMaxEncodedPayload(limit int) int {
	// 64+64+64+62 octets, needs to be base32-decodable.
	maxLengthName, err := dns.NewName([][]byte{
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	})
	if err != nil {
		panic(err)
	}
	{
		// Compute the encoded length of maxLengthName and that its
		// length is actually at the maximum of 255 octets.
		n := 0
		for _, label := range maxLengthName {
			n += len(label) + 1
		}
		n += 1 // For the terminating null label.
		if n != 255 {
			panic(fmt.Sprintf("max-length name is %d octets, should be %d %s", n, 255, maxLengthName))
		}
	}

	queryLimit := uint16(limit)
	if int(queryLimit) != limit {
		queryLimit = 0xffff
	}
	query := &dns.Message{
		Question: []dns.Question{
			{
				Name:  maxLengthName,
				Type:  dns.RRTypeTXT,
				Class: dns.RRTypeTXT,
			},
		},
		// EDNS(0)
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: queryLimit, // requester's UDP payload size
				TTL:   0,          // extended RCODE and flags
				Data:  []byte{},
			},
		},
	}
	resp, _ := responseFor(query, [][]byte{})
	// As in sendLoop.
	resp.Answer = []dns.RR{
		{
			Name:  query.Question[0].Name,
			Type:  query.Question[0].Type,
			Class: query.Question[0].Class,
			TTL:   responseTTL,
			Data:  nil, // will be filled in below
		},
	}

	// Binary search to find the maximum payload length that does not result
	// in a wire-format message whose length exceeds the limit.
	low := 0
	high := 32768
	for low+1 < high {
		mid := (low + high) / 2
		resp.Answer[0].Data = dns.EncodeRDataTXT(make([]byte, mid))
		buf, err := resp.WireFormat()
		if err != nil {
			panic(err)
		}
		if len(buf) <= limit {
			low = mid
		} else {
			high = mid
		}
	}

	return low
}

func run(privkey []byte, domain dns.Name, upstream string, dnsConn net.PacketConn) error {
	defer func() {
		_ = dnsConn.Close()
	}()

	log.Printf("pubkey %x", noise.PubkeyFromPrivkey(privkey))

	// We have a variable amount of room in which to encode downstream
	// packets in each response, because each response must contain the
	// query's Question section, which is of variable length. But we cannot
	// give dynamic packet size limits to KCP; the best we can do is set a
	// global maximum which no packet will exceed. We choose that maximum to
	// keep the UDP payload size under maxUDPPayload, even in the worst case
	// of a maximum-length name in the query's Question section.
	maxEncodedPayload := computeMaxEncodedPayload(maxUDPPayload)
	// 2 bytes accounts for a packet length prefix.
	mtu := maxEncodedPayload - 2
	if mtu < 80 {
		if mtu < 0 {
			mtu = 0
		}
		return fmt.Errorf("maximum UDP payload size of %d leaves only %d bytes for payload", maxUDPPayload, mtu)
	}
	log.Printf("effective MTU %d", mtu)

	// Start up the virtual PacketConn for turbotunnel.
	ttConn := turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, idleTimeout*2)
	ln, err := kcp.ServeConn(nil, 0, 0, ttConn)
	if err != nil {
		return fmt.Errorf("opening KCP listener: %v", err)
	}
	defer func() {
		_ = ln.Close()
	}()
	go func() {
		err := acceptSessions(ln, privkey, mtu, upstream)
		if err != nil {
			log.Printf("acceptSessions: %v", err)
		}
	}()

	ch := make(chan *record, 100)
	defer close(ch)

	// We could run multiple copies of sendLoop; that would allow more time
	// for each response to collect downstream data before being evicted by
	// another response that needs to be sent.
	go func() {
		err := sendLoop(dnsConn, ttConn, ch, maxEncodedPayload)
		if err != nil {
			log.Printf("sendLoop: %v", err)
		}
	}()

	return recvLoop(domain, dnsConn, ttConn, ch)
}

func main() {
	var genKey bool
	var privkeyFilename string
	var privkeyString string
	var pubkeyFilename string
	var configFile string // Added
	var apiAddr string

	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s -gen-key -privkey-file PRIVKEYFILE -pubkey-file PUBKEYFILE
  TOR_PT_MANAGED_TRANSPORT_VER=1 TOR_PT_SERVER_TRANSPORTS=dnstt TOR_PT_SERVER_BINDADDR=dnstt-ADDR TOR_PT_ORPORT=UPSTREAMADDR %[1]s [-config config.json] -privkey-file server.key t.example.com
...
`, os.Args[0])
		flag.PrintDefaults()
	}
	flag.BoolVar(&genKey, "gen-key", false, "generate a server keypair; print to stdout or save to files")
	flag.IntVar(&maxUDPPayload, "mtu", maxUDPPayload, "maximum size of DNS responses")
	flag.StringVar(&privkeyString, "privkey", "", fmt.Sprintf("server private key (%d hex digits)", noise.KeyLen*2))
	flag.StringVar(&privkeyFilename, "privkey-file", "", "read server private key from file (with -gen-key, write to file)")
	flag.StringVar(&pubkeyFilename, "pubkey-file", "", "with -gen-key, write server public key to file")
	flag.StringVar(&configFile, "config", "/etc/dnstt/static_records.json", "path to JSON config file for static records") // Added
	flag.StringVar(&apiAddr, "api", "", "HTTP API listen address (e.g., 127.0.0.1:8080). Leave empty to disable")
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.LUTC)

	if err := loadConfig(configFile); err != nil {
		log.Printf("warning: could not load static config from %s: %v", configFile, err)
	}

	if apiAddr != "" {
		startAPI(apiAddr, configFile)
	}

	if genKey {
		// -gen-key mode.
		if flag.NArg() != 0 || privkeyString != "" {
			flag.Usage()
			os.Exit(1)
		}
		if err := generateKeypair(privkeyFilename, pubkeyFilename); err != nil {
			log.Printf("cannot generate keypair: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Ordinary server mode.
		if flag.NArg() != 1 {
			flag.Usage()
			os.Exit(1)
		}
		domain, err := dns.ParseName(flag.Arg(0))
		if err != nil {
			log.Printf("invalid domain %+q: %v\n", flag.Arg(0), err)
			os.Exit(1)
		}

		ptInfo, err := pt.ServerSetup(nil)
		if err != nil {
			log.Fatalf("error in setup: %s", err)
		}

		upstream := ptInfo.OrAddr.String()
		// We keep upstream as a string in order to eventually pass it
		// to net.Dial in handleStream. But for the sake of displaying
		// an error or warning at startup, rather than only when the
		// first stream occurs, we apply some parsing and name
		// resolution checks here.
		{
			upstreamHost, _, err := net.SplitHostPort(upstream)
			if err != nil {
				// host:port format is required in all cases, so
				// this is a fatal error.
				log.Printf("cannot parse upstream address %+q: %v\n", upstream, err)
				os.Exit(1)
			}
			upstreamIPAddr, err := net.ResolveIPAddr("ip", upstreamHost)
			if err != nil {
				// Failure to resolve the host portion is only a
				// warning. The name will be re-resolved on each
				// net.Dial in handleStream.
				log.Printf("warning: cannot resolve upstream host %+q: %v", upstreamHost, err)
			} else if upstreamIPAddr.IP == nil {
				// Handle the special case of an empty string
				// for the host portion, which resolves to a nil
				// IP. This is a fatal error as we will not be
				// able to dial this address.
				log.Printf("cannot parse upstream address %+q: missing host in address\n", upstream)
				os.Exit(1)
			}
		}

		if pubkeyFilename != "" {
			log.Printf("-pubkey-file may only be used with -gen-key\n")
			os.Exit(1)
		}

		var privkey []byte
		if privkeyFilename != "" && privkeyString != "" {
			log.Printf("only one of -privkey and -privkey-file may be used\n")
			os.Exit(1)
		} else if privkeyFilename != "" {
			var err error
			privkey, err = readKeyFromFile(privkeyFilename)
			if err != nil {
				log.Printf("cannot read privkey from file: %v\n", err)
				os.Exit(1)
			}
		} else if privkeyString != "" {
			var err error
			privkey, err = noise.DecodeKey(privkeyString)
			if err != nil {
				log.Printf("privkey format error: %v\n", err)
				os.Exit(1)
			}
		}
		if len(privkey) == 0 {
			log.Println("generating a temporary one-time keypair")
			log.Println("use the -privkey or -privkey-file option for a persistent server keypair")
			var err error
			privkey, err = noise.GeneratePrivkey()
			if err != nil {
				log.Println(err)
				os.Exit(1)
			}
		}

		connections := make([]net.PacketConn, 0)
		for _, bindaddr := range ptInfo.Bindaddrs {
			if bindaddr.MethodName != ptMethodName {
				_ = pt.SmethodError(bindaddr.MethodName, "no such method")
				continue
			}

			// We're not capable of listening on port 0 (i.e., an ephemeral port
			// unknown in advance).
			if bindaddr.Addr.Port == 0 {
				err := fmt.Errorf(
					"cannot listen on port %d; configure a port with TOR_PT_SERVER_BINDADDR",
					bindaddr.Addr.Port)
				log.Printf("error opening listener: %s", err)
				_ = pt.SmethodError(bindaddr.MethodName, err.Error())
				continue
			}

			udpAddr := bindaddr.Addr.String()
			dnsConn, err := net.ListenPacket("udp", udpAddr)
			if err != nil {
				log.Printf("opening UDP listener: %v\n", err)
				_ = pt.SmethodError(bindaddr.MethodName, err.Error())
				continue
			}

			defer func() {
				_ = dnsConn.Close()
			}()

			go func() {
				err := run(privkey, domain, upstream, dnsConn)
				if err != nil {
					log.Print(err)
				}
			}()

			pt.SmethodArgs(bindaddr.MethodName, bindaddr.Addr, pt.Args{})
			connections = append(connections, dnsConn)
		}

		pt.SmethodsDone()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGTERM)

		if os.Getenv("TOR_PT_EXIT_ON_STDIN_CLOSE") == "1" {
			// This environment variable means we should treat EOF on stdin
			// just like SIGTERM: https://bugs.torproject.org/15435.
			go func() {
				if _, err := io.Copy(ioutil.Discard, os.Stdin); err != nil {
					log.Printf("error copying os.Stdin to ioutil.Discard: %v", err)
				}
				log.Printf("synthesizing SIGTERM because of stdin close")
				sigChan <- syscall.SIGTERM
			}()
		}

		// Wait for a signal.
		sig := <-sigChan

		// Signal received, shut down.
		log.Printf("caught signal %q, exiting", sig)
		for _, conn := range connections {
			_ = conn.Close()
		}
	}
}
