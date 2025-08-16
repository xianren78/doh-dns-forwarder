package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

const dnsCT = "application/dns-message"

// ======== Flags ========
var (
	// UDP listener
	flListen = flag.String("listen", ":8053", "UDP listen address for DNS (e.g. :53, 127.0.0.1:8053)") // 默认避开 5353
	// Upstream DoH
	flURL      = flag.String("u", "", "DoH URL, e.g. https://example.com/dns-query")
	flHost     = flag.String("host", "", "override Host header & TLS SNI (e.g. doh.example.com)")
	flConnect  = flag.String("connect", "", "connect to this addr (host:port), still use -u for scheme/path")
	flHTTP1    = flag.Bool("http1", false, "force HTTP/1.1 (disable h2, conservative mode)")
	flUA       = flag.String("ua", "mosdns-x/4.6.0", "User-Agent to send")
	flInsecure = flag.Bool("insecure", false, "skip TLS certificate verification (NOT recommended)")

	// ECS / EDNS
	flECS4       = flag.String("ecs4", "", "ECS IPv4 CIDR, e.g. 203.0.113.0/24 (overrides client)")
	flECS6       = flag.String("ecs6", "", "ECS IPv6 CIDR, e.g. 2001:db8::/56 (overrides client)")
	flECSAuto    = flag.Bool("ecs-auto", false, "derive ECS from client source IP (/24 for v4, /56 for v6; tunable via -ecs4mask/-ecs6mask)")
	flECS4Mask   = flag.Int("ecs4mask", 24, "mask to use when -ecs-auto and client is IPv4")
	flECS6Mask   = flag.Int("ecs6mask", 56, "mask to use when -ecs-auto and client is IPv6")
	flRespectECS = flag.Bool("respect-client-ecs", true, "if client sent ECS, keep it (true) or override with our ECS (false)")
	flSetDO      = flag.Bool("do", false, "set DO (DNSSEC OK) bit when adding EDNS (does not remove client DO if present)")
	flPad        = flag.Int("pad", 0, "EDNS padding target block size (0=disable)")
	flCookieHex  = flag.String("cookie", "", "EDNS cookie (hex, 8+ bytes; client cookie uses first 8 bytes)")
	flEDNSSize   = flag.Int("edns-size", 1232, "EDNS0 UDP payload size upper bound (default 1232)")

	// 网络与日志
	flTimeout    = flag.Duration("t", 6*time.Second, "per-query DoH timeout")
	flUDPBuf     = flag.Int("udp-buf", 4096, "UDP read buffer size")
	flLogQueries = flag.Bool("logq", false, "log queries and upstream results")
)

const safeMinEDNS = 512 // 规范要求的最小值

// ======== HTTP client builder ========
type dohClient struct {
	client    *http.Client
	reqURL    *url.URL
	host      string
	connect   string
	http1     bool
	userAgent string
	timeout   time.Duration
	insecure  bool
}

func newDOHClient() (*dohClient, error) {
	if *flURL == "" {
		return nil, fmt.Errorf("missing -u DoH URL")
	}
	u, err := url.Parse(*flURL)
	if err != nil {
		return nil, fmt.Errorf("bad -u: %w", err)
	}
	tlsCfg := &tls.Config{
		ServerName: *flHost, // 为空则使用 URL Host
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	}
	if *flHTTP1 {
		tlsCfg.NextProtos = []string{"http/1.1"}
	}
	if *flInsecure {
		tlsCfg.InsecureSkipVerify = true
	}

	dialer := &net.Dialer{
		Timeout:   *flTimeout / 2, // 连接阶段更紧
		KeepAlive: 30 * time.Second,
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if *flConnect != "" {
				addr = *flConnect
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:       tlsCfg,
		ForceAttemptHTTP2:     !*flHTTP1,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   *flTimeout / 2,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: *flTimeout / 2,
		Proxy:                 http.ProxyFromEnvironment,
		DisableCompression:    false,
	}
	if *flHTTP1 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{} // 禁 h2
	}

	c := &http.Client{Transport: tr, Timeout: *flTimeout}
	return &dohClient{
		client:    c,
		reqURL:    u,
		host:      *flHost,
		connect:   *flConnect,
		http1:     *flHTTP1,
		userAgent: *flUA,
		timeout:   *flTimeout,
		insecure:  *flInsecure,
	}, nil
}

func (dc *dohClient) buildH1Client() *http.Client {
	// 用于 h2 失败后的单次 h1 重试
	dialer := &net.Dialer{
		Timeout:   dc.timeout / 2,
		KeepAlive: 30 * time.Second,
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if dc.connect != "" {
				addr = dc.connect
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName: dc.host,
			NextProtos: []string{"http/1.1"},
			MinVersion: tls.VersionTLS12,
			// Insecure 同上配置
			InsecureSkipVerify: dc.insecure,
		},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   dc.timeout / 2,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: dc.timeout / 2,
		Proxy:                 http.ProxyFromEnvironment,
	}
	return &http.Client{Transport: tr, Timeout: dc.timeout}
}

func (dc *dohClient) roundTripDNS(wire []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dc.timeout)
	defer cancel()

	// 首选 POST
	req, err := http.NewRequestWithContext(ctx, "POST", dc.reqURL.String(), bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", dnsCT)
	req.Header.Set("Accept", dnsCT)
	if dc.userAgent != "" {
		req.Header.Set("User-Agent", dc.userAgent)
	}
	if dc.host != "" {
		req.Host = dc.host
	}

	res, err := dc.client.Do(req)
	if err != nil {
		// h2 失败 → 用 h1 再试一次
		if !dc.http1 {
			h1c := dc.buildH1Client()
			res, err = h1c.Do(req.Clone(ctx))
			if err != nil {
				return nil, err
			}
			defer res.Body.Close()
		} else {
			return nil, err
		}
	} else {
		defer res.Body.Close()
	}

	// 若 POST 返回 404/415 等，尝试 GET 兜底
	if res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusUnsupportedMediaType {
		return dc.tryGET(ctx, wire)
	}

	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 1024))
		return nil, fmt.Errorf("upstream HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(b)))
	}

	mt, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if mt != dnsCT {
		return nil, fmt.Errorf("unexpected content-type: %q", res.Header.Get("Content-Type"))
	}
	return io.ReadAll(io.LimitReader(res.Body, 65536))
}

func (dc *dohClient) tryGET(ctx context.Context, wire []byte) ([]byte, error) {
	enc := base64.RawURLEncoding.EncodeToString(wire) // RFC8484 要求 base64url 无填充
	u := *dc.reqURL
	q := u.Query()
	q.Set("dns", enc)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", dnsCT)
	if dc.userAgent != "" {
		req.Header.Set("User-Agent", dc.userAgent)
	}
	if dc.host != "" {
		req.Host = dc.host
	}

	res, err := dc.client.Do(req)
	if err != nil {
		// 再做一次 h1 兜底
		if !dc.http1 {
			h1c := dc.buildH1Client()
			res, err = h1c.Do(req.Clone(ctx))
			if err != nil {
				return nil, err
			}
			defer res.Body.Close()
		} else {
			return nil, err
		}
	} else {
		defer res.Body.Close()
	}

	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 1024))
		return nil, fmt.Errorf("GET upstream HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(b)))
	}
	mt, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if mt != dnsCT {
		return nil, fmt.Errorf("GET unexpected content-type: %q", res.Header.Get("Content-Type"))
	}
	return io.ReadAll(io.LimitReader(res.Body, 65536))
}

// ======== ECS helpers ========
func parseCIDR(cidr string) (*dns.EDNS0_SUBNET, error) {
	ip, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, err
	}
	fam := uint16(1)
	if ip.To4() == nil {
		fam = 2
	}
	ones, _ := ipnet.Mask.Size()
	ip = ip.Mask(ipnet.Mask) // network address
	return &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        fam,
		SourceNetmask: uint8(ones),
		SourceScope:   0,
		Address:       ip,
	}, nil
}

func ecsFromClient(src net.IP, mask4, mask6 int) *dns.EDNS0_SUBNET {
	if src == nil {
		return nil
	}
	if v4 := src.To4(); v4 != nil {
		ipnet := &net.IPNet{IP: v4.Mask(net.CIDRMask(mask4, 32)), Mask: net.CIDRMask(mask4, 32)}
		ecs, _ := parseCIDR(ipnet.String())
		return ecs
	}
	ipnet := &net.IPNet{IP: src.Mask(net.CIDRMask(mask6, 128)), Mask: net.CIDRMask(mask6, 128)}
	ecs, _ := parseCIDR(ipnet.String())
	return ecs
}

// insert/override EDNS with ECS/Cookie/DO/Pad
func applyEDNSOptions(msg *dns.Msg, ecsOpt *dns.EDNS0_SUBNET, respectClientECS bool, setDO bool, padTo int, cookieHex string, ednsUpper int) error {
	// 安全的 UDP Payload 上限（默认 1232，但不小于 512）
	if ednsUpper < safeMinEDNS {
		ednsUpper = safeMinEDNS
	}

	var opt *dns.OPT
	if msg.IsEdns0() == nil {
		msg.SetEdns0(uint16(ednsUpper), setDO)
		opt = msg.IsEdns0()
	} else {
		opt = msg.IsEdns0()
		// 限制回应尺寸：取 min(客户端宣告, ednsUpper)，且不小于 512
		udpSize := int(opt.UDPSize())
		if udpSize == 0 || udpSize > ednsUpper {
			opt.SetUDPSize(uint16(ednsUpper))
		} else if udpSize < safeMinEDNS {
			opt.SetUDPSize(safeMinEDNS)
		}
		// DO 位：若客户端已设就保持，否则按标志设置
		if setDO && (opt.Hdr.Ttl&0x8000) == 0 {
			opt.Hdr.Ttl |= 0x8000
		}
	}

	// Respect or override ECS
	if ecsOpt != nil {
		hasClientECS := false
		for _, o := range opt.Option {
			if _, ok := o.(*dns.EDNS0_SUBNET); ok {
				hasClientECS = true
				break
			}
		}
		if !hasClientECS || !respectClientECS {
			// remove old ECS if overriding
			if !respectClientECS {
				newOpts := make([]dns.EDNS0, 0, len(opt.Option))
				for _, o := range opt.Option {
					if _, ok := o.(*dns.EDNS0_SUBNET); !ok {
						newOpts = append(newOpts, o)
					}
				}
				opt.Option = newOpts
			}
			opt.Option = append(opt.Option, ecsOpt)
		}
	}

	// Cookie (client cookie 8 bytes)
	if cookieHex != "" {
		raw, err := hex.DecodeString(strings.TrimSpace(cookieHex))
		if err != nil {
			return fmt.Errorf("bad -cookie: %w", err)
		}
		if len(raw) < 8 {
			return fmt.Errorf("edns client cookie must be >=8 bytes")
		}
		if len(raw) > 8 {
			raw = raw[:8]
		}
		opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{Cookie: string(raw)})
	}

	// Padding
	if padTo > 0 {
		wireNow, _ := msg.Pack()
		if rem := len(wireNow) % padTo; rem != 0 {
			if padLen := padTo - rem; padLen > 0 && padLen <= 1200 {
				opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: make([]byte, padLen)})
			}
		}
	}

	// Ensure packable
	if _, err := msg.Pack(); err != nil {
		return fmt.Errorf("pack after EDNS apply: %w", err)
	}
	return nil
}

// ======== UDP server ========
func writeSERVFAIL(udpConn *net.UDPConn, src *net.UDPAddr, req *dns.Msg) {
	if req == nil {
		return
	}
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeServerFailure)
	if out, err := m.Pack(); err == nil {
		_, _ = udpConn.WriteToUDP(out, src)
	}
}

func handlePacket(dc *dohClient, udpConn *net.UDPConn, pkt []byte, src *net.UDPAddr, ecs4, ecs6 *dns.EDNS0_SUBNET) {
	// Parse client message
	req := new(dns.Msg)
	if err := req.Unpack(pkt); err != nil {
		if *flLogQueries {
			log.Printf("from %s: bad DNS msg: %v", src, err)
		}
		// 格式错误不回包（也可考虑 FORMERR）
		return
	}
	origID := req.Id

	// Prepare upstream copy with ID=0 as per RFC 8484
	upReq := req.Copy()
	upReq.Id = 0

	// Apply EDNS/ECS
	var ecsToUse *dns.EDNS0_SUBNET
	// priority: manual ecs4/ecs6 if same family as client; else ecs-auto; else none
	if src.IP.To4() != nil {
		if *flECS4 != "" && ecs4 != nil {
			ecsToUse = ecs4
		} else if *flECSAuto {
			ecsToUse = ecsFromClient(src.IP, *flECS4Mask, *flECS6Mask)
		}
	} else {
		if *flECS6 != "" && ecs6 != nil {
			ecsToUse = ecs6
		} else if *flECSAuto {
			ecsToUse = ecsFromClient(src.IP, *flECS4Mask, *flECS6Mask)
		}
	}

	if err := applyEDNSOptions(upReq, ecsToUse, *flRespectECS, *flSetDO, *flPad, *flCookieHex, *flEDNSSize); err != nil {
		if *flLogQueries {
			log.Printf("from %s: EDNS apply err: %v", src, err)
		}
		writeSERVFAIL(udpConn, src, req)
		return
	}

	// Pack and send upstream
	wire, err := upReq.Pack()
	if err != nil {
		if *flLogQueries {
			log.Printf("from %s: pack err: %v", src, err)
		}
		writeSERVFAIL(udpConn, src, req)
		return
	}

	replyWire, err := dc.roundTripDNS(wire)
	if err != nil {
		if *flLogQueries {
			log.Printf("from %s: upstream err: %v", src, err)
		}
		writeSERVFAIL(udpConn, src, req)
		return
	}

	// Unpack, restore ID, re-pack
	resp := new(dns.Msg)
	if err := resp.Unpack(replyWire); err != nil {
		if *flLogQueries {
			log.Printf("from %s: upstream unpack err: %v", src, err)
		}
		writeSERVFAIL(udpConn, src, req)
		return
	}
	resp.Id = origID
	out, err := resp.Pack()
	if err != nil {
		if *flLogQueries {
			log.Printf("from %s: resp pack err: %v", src, err)
		}
		writeSERVFAIL(udpConn, src, req)
		return
	}

	// Send back
	if _, err := udpConn.WriteToUDP(out, src); err != nil && *flLogQueries {
		log.Printf("from %s: write udp err: %v", src, err)
	}
	if *flLogQueries {
		q := "<nil>"
		qt := "?"
		if len(req.Question) > 0 {
			q = req.Question[0].Name
			qt = dns.TypeToString[req.Question[0].Qtype]
		}
		log.Printf("OK %s %s from=%s ans=%d", q, qt, src.IP, len(resp.Answer))
	}
}

func main() {
	flag.Parse()
	if *flURL == "" {
		log.Fatal("missing -u DoH URL")
	}

	// Build ECS fixed options if provided
	var ecs4, ecs6 *dns.EDNS0_SUBNET
	var err error
	if *flECS4 != "" {
		ecs4, err = parseCIDR(*flECS4)
		if err != nil {
			log.Fatalf("bad -ecs4: %v", err)
		}
	}
	if *flECS6 != "" {
		ecs6, err = parseCIDR(*flECS6)
		if err != nil {
			log.Fatalf("bad -ecs6: %v", err)
		}
	}

	// Build DoH client
	dc, err := newDOHClient()
	if err != nil {
		log.Fatal(err)
	}

	// UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", *flListen)
	if err != nil {
		log.Fatalf("resolve listen: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("listen udp: %v", err)
	}
	defer udpConn.Close()
	_ = udpConn.SetReadBuffer(*flUDPBuf)

	log.Printf("DNS UDP forwarder listening on %s → DoH %s (UA=%q ECS4=%q ECS6=%q auto=%v edns-size<=%d)",
		udpAddr, *flURL, *flUA, *flECS4, *flECS6, *flECSAuto, *flEDNSSize)

	// graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	buf := make([]byte, 65535)
	for {
		udpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, src, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					log.Printf("shutting down...")
					return
				default:
					continue
				}
			}
			if ctx.Err() != nil {
				return
			}
			continue
		}
		// ✅ 关键：立刻复制数据，避免下一次 Read 覆盖
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go handlePacket(dc, udpConn, pkt, src, ecs4, ecs6)
	}
}
