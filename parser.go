package iptables_parser

import (
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"

	vd "github.com/leonnicolas/iptables_parser/validate_dns"
)

// Line represents a line in a iptables dump, e.g. generated with iptables-save.
// It is either Comment, Header, Default or Rule.
type Line interface{}

// Comment represents a comment in an iptables dump. Comments start with #.
type Comment struct {
	Content string
}

// Header represents a header in an iptables dump and introduce a new table. They start with *.
type Header struct {
	Content string
}

// Default represents a default rule. They start with :.
type Default struct {
	Chain   string
	Action  string
	Counter Counter
}

// Rule represents a rule in an iptables dump. Normally the start with -A.
// The parser treats the -A flag like any other flag, thus does not require
// the -A flag as the leading flag.
type Rule struct {
	Chain   string
	src     DNSOrIPPair
	dest    DNSOrIPPair
	comment string
	// Be aware that the protocol names can be different depending on your system.
	Protocol  StringPair
	IPv4      bool
	IPv6      bool
	Jump      Target
	Goto      Target
	InInterf  StringPair
	OutInterf StringPair
	outInterf string
	Fragment  BoolPair
	counter   Counter
	// Matches need to be a slice because order can matter. See man iptables-extension.
	Matches []Match
}

// DNSOrIPPair either holds an IP or DNS and a flag.
// The boolean not-flag is used when an address or
// DNS name is reverted with a "!" character.
type DNSOrIPPair struct {
	value DNSOrIP
	not   bool
}

// DNSOrIP represents either a DNS name or an IP address.
// IPs, as they are more specific, are preferred.
type DNSOrIP struct {
	// DNS must be a valid RFC 1123 subdomain.
	// +optional
	dNS string
	// IP must be a valid IP address.
	// +optional
	iP net.IPNet
}

// Set IP if string is a valid IP address, or DNS if string is a valid DNS name,
// else return error.
func (d *DNSOrIP) Set(s string) error {
	sn := s
	// TODO: this can probably be done in a nicer way.
	if !strings.Contains(sn, "/") {
		sn = sn + "/32"
	}
	if _, ipnet, err := net.ParseCIDR(sn); err == nil {
		d.iP = *ipnet
		return nil
	}
	if !vd.IsDNS(s) {
		return fmt.Errorf("%q is not a valid DNS name", s)
	}
	d.dNS = s
	return nil
}

// NewDNSOrIP takes a string and return a DNSOrIP, or an error.
// It tries to parse it as an IP, if this fails it will check,
// whether the input is a valid DNS name.
func NewDNSOrIP(s string) (*DNSOrIP, error) {
	ret := &DNSOrIP{}
	if err := ret.Set(s); err != nil {
		return nil, err
	}
	return ret, nil
}

// StringPair is a string with a flag.
type StringPair struct {
	Not   bool
	Value string
}

// BoolPair makes sense in the following case:
// You can specify a flag that does not accept any
// values. It is also possible to negate the flag with
// a "!". In the latter case, Not will be set to true.
// Value will be set to true, if the flag was used.
type BoolPair struct {
	Not   bool
	Value bool
}

// Counter represents the package and byte counters.
type Counter struct {
	packets uint64
	bytes   uint64
}

// Match represents one match expression from the iptables-extension.
// See man iptables-extenstion for more info.
type Match struct {
	Type  string
	Flags map[string]Flag
}

// Flag is flag, e.g. --dport 8080. It can be negated with a leading !.
// Sometimes a flag is followed by several arguments.
type Flag struct {
	Not    bool
	Values []string
}

type Target struct {
	Name  string
	Flags map[string]Flag
}

// Max buffer size of the ring buffer in the parser.
const BUF_SIZE = 10

// Parser represents a parser.
type Parser struct {
	s   *scanner
	buf struct {
		toks [BUF_SIZE]Token  // token buffer
		lits [BUF_SIZE]string // literal buffer
		p    int              // current position in the buffer (max=BUF_SIZE)
		n    int              // offset (max=BUF_SIZE)
	}
}

var matchModules map[string]struct{}
var targetExtensions map[string]struct{}

func init() {
	matchModules = make(map[string]struct{})
	for _, m := range []string{"addrtype", "ah", "bpf", "cgroup", "cluster", "comment", "connbytes", "connlabel", "connlimit", "connmark", "conntrack", "cpu", "dccp", "devgroup", "dscp", "dst", "ecn", "esp", "eui64", "frag", "hashlimit", "hbh", "helper", "hl", "icmp", "icmp6", "iprange", "ipv6header", "ipvs", "length", "limit", "mac", "mark", "mh", "multiport", "nfacct", "osf", "owner", "physdev", "pkttype", "policy", "quota", "rateest", "realm", "recent", "rpfilter", "rt", "sctp", "set", "socket", "state", "statistics", "string", "tcp", "tcpmss", "time", "tos", "ttl", "u32", "udp"} {
		matchModules[m] = struct{}{}
	}
	targetExtensions = make(map[string]struct{})
	for _, e := range []string{"AUDIT", "CHECKSUM", "CLASSIFY", "CLUSTERIP", "CONNMARK", "CONNSECMARK", "CT", "DNAT", "DNPT", "DSCP", "ECN", "HL", "HMARK", "IDLETIMER", "LED", "LOG", "MARK", "MASQUERADE", "NETMAP", "NFLOG", "NFQUEUE", "NOTRACK", "RATEEST", "REDIRECT", "REJECT", "SECMARK", "SET", "SNAT", "SNPT", "SYNPROXY", "TCPMSS", "TCPOPTSTRIP", "TEE", "TOS", "TPROXY", "TRACE", "TTL", "ULOG"} {
		targetExtensions[e] = struct{}{}
	}
}

// NewParser returns a new instance of Parser.
func NewParser(r io.Reader) *Parser {
	return &Parser{s: newScanner(r)}
}

// Parse parses one line and returns a Rule, Comment, Header or DEFAULT.
func (p *Parser) Parse() (Line, error) {
	tok, lit := p.scanIgnoreWhitespace()
	switch tok {
	case COMMENTLINE:
		return Comment{Content: lit}, nil
	case HEADER:
		return Header{Content: lit}, nil
	case FLAG:
		p.unscan(1)
		return p.parseRule()
	case COLON:
		return p.parseDefault(p.s.scanLine())
	case EOF:
		return nil, ErrEOF
	case NEWLINE:
		return nil, errors.New("empty line")
	default:
		return nil, NewParseError(fmt.Sprintf("unexpected format of first token: %s, skipping rest %q of the line", lit, p.s.scanLine()))
	}
}

var (
	regDefault *regexp.Regexp = regexp.MustCompile(`^\s*(\S+)\s+(\S+)\s+(\[\d*\:\d*\])\s*$`)
	regCounter *regexp.Regexp = regexp.MustCompile(`^\[(\d*)\:(\d*)\]$`)
)

func (p *Parser) parseDefault(lit string) (Line, error) {
	var r Default
	r.Chain = string(regDefault.ReplaceAll([]byte(lit), []byte("$1")))
	a := regDefault.ReplaceAll([]byte(lit), []byte("$2"))
	switch string(a) {
	case "-":
		r.Action = "NONE"
	case "ACCEPT":
		r.Action = "ACCEPT"
	case "DROP":
		r.Action = "DROP"
	default:
		r.Action = "UNKNOWN"
	}

	cs := regDefault.ReplaceAll([]byte(lit), []byte("$3"))
	c, err := parseCounter(cs)
	if err != nil {
		return nil, err
	}

	r.Counter = c
	return r, nil
}

// parseCounter parses something like "[0:100]"
func parseCounter(bytes []byte) (Counter, error) {
	var c Counter
	pc := regCounter.ReplaceAll(bytes, []byte("$1"))
	if i, err := strconv.ParseUint(string(pc), 10, 0); err != nil {
		return c, fmt.Errorf("Could not parse counter: %w", err)
	} else {
		c.packets = i
	}
	pc = regCounter.ReplaceAll(bytes, []byte("$2"))
	if i, err := strconv.ParseUint(string(pc), 10, 0); err != nil {
		return c, fmt.Errorf("Could not parse counter: %w", err)
	} else {
		c.bytes = i
	}
	return c, nil
}

// State for the state machine
type state int

const (
	// Only use even numbers, to have some local states, that can us odd numbers.
	sStart state = iota * 2
	sJ
	sGoto
	sA
	sIF // Interpret a flag
	sINotF
	sNot
	sError
)

func (p *Parser) parseRule() (Line, error) {
	var r Rule
	s := sStart
	var err error
	for tok, lit := p.scanIgnoreWhitespace(); tok != EOF && tok != NEWLINE; tok, lit = p.scanIgnoreWhitespace() {
		nextValue := false
		for !nextValue {
			nextValue = true
			switch s {
			case sStart:
				switch tok {
				case FLAG:
					s = sIF
					nextValue = false
				case NOT:
					s = sNot
				default:

					s = sError
					break
				}
			case sIF:
				switch {
				case isSrc(lit):
					s, err = p.parseAddr(&r.src, false)
				case isDest(lit):
					s, err = p.parseAddr(&r.dest, false)
				case lit == "-p" || lit == "--protocol":
					s, err = p.parseProtocol(&r.Protocol, false)
				case isMatch(lit):
					s, err = p.parseMatch(&r.Matches)
				case lit == "-A" || lit == "--append":
					s = sA
				case lit == "-j" || lit == "--jump":
					s, err = p.parseTarget(&r.Jump)
				case lit == "-g" || lit == "--goto":
					s, err = p.parseTarget(&r.Goto)
				case lit == "-i" || lit == "--in-interface":
					s, err = p.parseStringPair(&r.InInterf, false)
				case lit == "-o" || lit == "--out-interface":
					s, err = p.parseStringPair(&r.OutInterf, false)
				case lit == "-f" || lit == "--fragment":
					r.Fragment = BoolPair{Value: true}
					s = sStart
				case lit == "-4" || lit == "--ipv4":
					r.IPv4 = true
					s = sStart
				case lit == "-6" || lit == "--ipv6":
					r.IPv6 = true
					s = sStart
				default:
					err = fmt.Errorf("unknown flag %q found", lit)
					s = sError
				}
			case sINotF:
				switch {
				case isSrc(lit):
					s, err = p.parseAddr(&r.src, true)
				case isDest(lit):
					s, err = p.parseAddr(&r.dest, true)
				case lit == "-p" || lit == "--protocol":
					s, err = p.parseProtocol(&r.Protocol, true)
				case lit == "-i" || lit == "--in-interface":
					s, err = p.parseStringPair(&r.InInterf, true)
				case lit == "-o" || lit == "--out-interface":
					s, err = p.parseStringPair(&r.OutInterf, true)
				case lit == "-f" || lit == "--fragment":
					r.Fragment = BoolPair{Value: true, Not: true}
					s = sStart
				default:
					err = fmt.Errorf("encountered unknown flag %q, or flag can not be negated with \"!\"", lit)
					s = sError
				}
			case sA:
				r.Chain = lit
				s = sStart

			case sNot:
				switch tok {
				case FLAG:
					nextValue = false
					s = sINotF
				default:
					err = fmt.Errorf("unexpected token %q, expected identifier", lit)
					s = sError
				}
			case sError:
				return nil, fmt.Errorf("failed to parse line, skipping rest %q of the line: %w", p.s.scanLine(), err)
			default:
				nextValue = true

			}
		}

	}
	return r, nil
}

// parseProtocol is not restricted on protocol types because the names
// can depend on the underlying system. E.g. ipv4 is called ipencap
// in Gentoo based systems.
func (p *Parser) parseProtocol(r *StringPair, not bool) (state, error) {
	tok, lit := p.scanIgnoreWhitespace()
	if tok == NEWLINE || tok == EOF {
		return sError, errors.New("unexpected end of line while parsing protocol")
	}
	*r = StringPair{
		Not:   not,
		Value: lit,
	}
	return sStart, nil
}

func (p *Parser) parseAddr(r *DNSOrIPPair, not bool) (state, error) {
	tok, lit := p.scanIgnoreWhitespace()
	if tok == NEWLINE || tok == EOF {
		return sError, errors.New("unexpected end of line while parsing address")
	}
	doi, err := NewDNSOrIP(lit)
	if err != nil {
		return sError, err
	}
	*r = DNSOrIPPair{value: *doi, not: not}
	return sStart, nil
}

// parseStringPair
func (p *Parser) parseStringPair(sp *StringPair, not bool) (state, error) {
	tok, lit := p.scanIgnoreWhitespace()
	if tok != IDENT {
		*sp = StringPair{Value: "", Not: not}
		p.unscan(1)
		return sStart, errors.New("unexpected token, expected IDENT")
	} else {
		*sp = StringPair{Value: lit, Not: not}
	}
	return sStart, nil
}

func mod(a, b int) int {
	return (a%b + b) % b
}

// scan returns the next token from the underlying scanner.
// If a token has been unscanned then read that instead.
func (p *Parser) scan() (tok Token, lit string) {
	// If we have a token on the buffer, then return it.
	if p.buf.n != 0 {
		p.buf.n--
		return p.buf.toks[mod(p.buf.p-p.buf.n-1, BUF_SIZE)], p.buf.lits[mod(p.buf.p-p.buf.n-1, BUF_SIZE)]
	}

	// Otherwise read the next token from the scanner.
	tok, lit = p.s.scan()
	// Save it to the buffer in case we unscan later.
	p.buf.toks[p.buf.p], p.buf.lits[p.buf.p] = tok, lit
	p.buf.p++
	p.buf.p %= BUF_SIZE

	return
}

// scanIgnoreWhitespace scans the next non-whitespace token.
func (p *Parser) scanIgnoreWhitespace() (tok Token, lit string) {
	tok, lit = p.scan()
	for tok == WS {
		tok, lit = p.scan()
	}
	return
}

// unscan reverts the pointer on the buffer, callers should not unscan more then what was
// previously read, or values larger then BUF_SIZE.
func (p *Parser) unscan(n int) {
	if p.buf.n+n >= BUF_SIZE {
		panic("size exceeds buffer")
	}
	p.buf.n += n
}

func (p *Parser) unscanIgnoreWhitespace(n int) error {
	for i := 0; i < BUF_SIZE; i++ {
		if p.buf.toks[p.buf.n] == ILLEGAL {
			break
		}
		if p.buf.toks[p.buf.n] == WS {
			p.unscan(1)
		} else {
			if n--; n == 0 {
				return nil
			}
		}
	}
	return errors.New("buffer has no none whitespace characters")
}

func isSrc(s string) bool {
	return s == "-s" || s == "--src" || s == "--source"
}

func isDest(s string) bool {
	return s == "-d" || s == "--dest" || s == "--dst" || s == "--destination"
}

func isMatch(s string) bool {
	return s == "-m" || s == "--match"
}
