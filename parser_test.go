package iptables_parser

import (
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
)

var (
	_true  bool = true
	_false bool = false
)

func parseCIDR(s string) net.IPNet {
	if !strings.Contains(s, "/") {
		s = s + "/32"
	}
	_, r, err := net.ParseCIDR(s)
	if err != nil {
		panic(err.Error())
	}
	return *r
}

func TestDNSOrIPPair_Spec(t *testing.T) {
	for i, tc := range []struct {
		d DNSOrIPPair
		f string
		r []string
	}{
		{
			d: DNSOrIPPair{
				Not: false,
				Value: DNSOrIP{
					iP: parseCIDR("10.0.0.0/24"),
				},
			},
			f: "-d",
			r: []string{"-d", "10.0.0.0/24"},
		},
		{
			d: DNSOrIPPair{
				Not: true,
				Value: DNSOrIP{
					iP: parseCIDR("10.0.0.0/24"),
				},
			},
			f: "-d",
			r: []string{"!", "-d", "10.0.0.0/24"},
		},
	} {
		if res := tc.d.Spec(tc.f); !reflect.DeepEqual(res, tc.r) {
			t.Errorf("test %d:\n\texp=%q\n\tgot=%q\n", i, tc.r, res)
		}
	}
}

func TestStringPair_Spec(t *testing.T) {
	for i, tc := range []struct {
		p StringPair
		f string
		r []string
	}{
		{
			p: StringPair{
				Not:   false,
				Value: "foo",
			},
			f: "-p",
			r: []string{"-p", "foo"},
		},
		{
			p: StringPair{
				Not:   true,
				Value: "bar",
			},
			f: "-i",
			r: []string{"!", "-i", "bar"},
		},
	} {
		if res := tc.p.Spec(tc.f); !reflect.DeepEqual(res, tc.r) {
			t.Errorf("test %d:\n\texp=%q\n\tgot=%q\n", i, tc.r, res)
		}
	}
}

func TestFlag_String(t *testing.T) {
	for i, tc := range []struct {
		p Flag
		f string
		r string
	}{
		{
			p: Flag{
				Not:    false,
				Values: []string{"foo"},
			},
			f: "-p",
			r: "-p foo",
		},
		{
			p: Flag{
				Not:    true,
				Values: []string{"bar", "foo"},
			},
			f: "-i",
			r: "! -i bar foo",
		},
	} {
		if res := tc.p.String(tc.f); !reflect.DeepEqual(res, tc.r) {
			t.Errorf("test %d:\n\texp=%q\n\tgot=%q\n", i, tc.r, res)
		}
	}
}

func TestMatch_String(t *testing.T) {
	for i, tc := range []struct {
		p Match
		r string
	}{
		{
			p: Match{
				Type: "comment",
				Flags: map[string]Flag{
					"comment": {
						Values: []string{"hallo"},
					},
				},
			},
			r: "-m comment --comment hallo",
		},
		{
			p: Match{
				Type: "tcp",
				Flags: map[string]Flag{
					"tcp-options": {
						Not:    true,
						Values: []string{"bla", "blub"},
					},
				},
			},
			r: "-m tcp ! --tcp-options bla blub",
		},
	} {
		if res := tc.p.String(); !reflect.DeepEqual(res, tc.r) {
			t.Errorf("test %d:\n\texp=%q\n\tgot=%q\n", i, tc.r, res)
		}
	}
}

func TestTarget_String(t *testing.T) {
	for i, tc := range []struct {
		p Target
		f string
		r string
	}{
		{
			p: Target{
				Name: "foo",
				Flags: map[string]Flag{
					"bar": {
						Values: []string{"foo"},
					},
				},
			},
			f: "-g",
			r: "-g foo --bar foo",
		},
		{
			p: Target{
				Name: "foo",
				Flags: map[string]Flag{
					"bar": {
						Not:    true,
						Values: []string{"foo", "bar"},
					},
				},
			},
			f: "-j",
			r: "-j foo ! --bar foo bar",
		},
	} {
		if res := tc.p.String(tc.f); !reflect.DeepEqual(res, tc.r) {
			t.Errorf("test %d:\n\texp=%q\n\tgot=%q\n", i, tc.r, res)
		}
	}
}

func TestRule_Spec(t *testing.T) {
	for i, tc := range []struct {
		rule Rule
		res  []string
	}{
		{
			rule: Rule{
				Chain: "foo",
				Source: &DNSOrIPPair{
					Value: DNSOrIP{
						iP: parseCIDR("192.168.178.2"),
					},
					Not: true,
				},
				Destination: &DNSOrIPPair{Value: DNSOrIP{iP: parseCIDR("1.1.1.1")}, Not: true},
			},
			res: []string{"!", "-s", "192.168.178.2/32", "!", "-d", "1.1.1.1/32"},
		},
	} {
		if res := tc.rule.Spec(); !reflect.DeepEqual(res, tc.res) {
			t.Errorf("test %d:\n\texp=%q\n\tgot=%q\n", i, tc.res, res)
		}
	}
}

func TestRule_String(t *testing.T) {
	for i, tc := range []struct {
		rule Rule
		res  string
	}{
		{
			rule: Rule{
				Chain: "foo",
				Source: &DNSOrIPPair{
					Value: DNSOrIP{
						iP: parseCIDR("192.168.178.2"),
					},
					Not: true,
				},
				Destination: &DNSOrIPPair{Value: DNSOrIP{iP: parseCIDR("1.1.1.1")}, Not: true},
			},
			res: "-A foo ! -s 192.168.178.2/32 ! -d 1.1.1.1/32",
		},
		{
			rule: Rule{
				Chain: "KUBE-POSTROUTING",
				Matches: []Match{
					{
						Type: "comment",
						Flags: map[string]Flag{
							"comment": {Values: []string{`kubernetes service traffic requiring SNAT`}},
						},
					},
				},
				Jump: &Target{
					Name: "MASQUERADE",
					Flags: map[string]Flag{
						"to-ports": {
							Values: []string{"200-1000"},
						},
					},
				},
			},
			res: `-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE --to-ports 200-1000`,
		},
	} {
		if res := tc.rule.String(); !reflect.DeepEqual(res, tc.res) {
			t.Errorf("test %d:\n\texp=%q\n\tgot=%q\n", i, tc.res, res)
		}
	}
}

func Test_NewRuleFromSpec(t *testing.T) {
	for i, tc := range []struct {
		spec  []string
		chain string
		rule  Rule
	}{
		{
			spec:  []string{"-p", "tcp", "-j", "RETURN"},
			chain: "foo",
			rule: Rule{
				Chain: "foo",
				Protocol: &StringPair{
					Value: "tcp",
				},
				Jump: &Target{
					Name: "RETURN",
				},
			},
		},
	} {
		if r, err := NewRuleFromSpec(tc.chain, tc.spec...); !reflect.DeepEqual(*r, tc.rule) {
			if err != nil {
				t.Errorf("test case %d unexpected error:\n\texp=%q\n\tgot=%q\n", i, tc.rule, r)
			}
			t.Errorf("test case %d rule missmatch:\n\texp=%#v\n\tgot=%#v\n", i, tc.rule, r)
		}
	}
}

func TestParser_Parse(t *testing.T) {
	for i, tc := range []struct {
		name string
		s    string
		r    Line
		err  error
	}{
		{
			name: "parse empty string",
			s:    "",
			r:    nil,
			err:  io.EOF,
		},
		{
			name: "parse comment",
			s:    "# hello you.",
			r:    Comment{Content: " hello you."},
			err:  nil,
		},
		{
			name: "parse more comment",
			s:    "# hello you.\ncutey",
			r:    Comment{Content: " hello you."},
			err:  nil,
		},
		{
			name: "parse header",
			s:    "*hello you.\ncutey",
			r:    Header{Content: "hello you."},
			err:  nil,
		},
		{
			name: "parse default rule",
			s:    ":hello ACCEPT [10:100]",
			r: Policy{
				Chain:  "hello",
				Action: "ACCEPT",
				Counter: &Counter{
					packets: 10,
					bytes:   100,
				},
			},
			err: nil,
		},
		{
			name: "parse default rule",
			s:    ":hello-chain DROP [0:100]",
			r: Policy{
				Chain:  "hello-chain",
				Action: "DROP",
				Counter: &Counter{
					packets: 0,
					bytes:   100,
				},
			},
			err: nil,
		},
		{
			name: "parse default rule without counter",
			s:    ":hello-chain DROP",
			r: Policy{
				Chain:  "hello-chain",
				Action: "DROP",
				Counter: &Counter{
					packets: 0,
					bytes:   0,
				},
			},
			err: nil,
		},
		{
			name: "parse policy",
			s:    "-P hello-chain DROP",
			r: Policy{
				Chain:       "hello-chain",
				Action:      "DROP",
				UserDefined: &_false,
			},
			err: nil,
		},
		{
			name: "parse userdefined policy",
			s:    "-N hello-chain",
			r: Policy{
				Chain:       "hello-chain",
				UserDefined: &_true,
			},
			err: nil,
		},
		{
			name: "parse rule",
			s:    "-A foo ! -s 192.168.178.2 ! --dst 1.1.1.1",
			r: Rule{
				Chain: "foo",
				Source: &DNSOrIPPair{
					Value: DNSOrIP{
						iP: parseCIDR("192.168.178.2"),
					},
					Not: true,
				},
				Destination: &DNSOrIPPair{Value: DNSOrIP{iP: parseCIDR("1.1.1.1")}, Not: true},
			},
			err: nil,
		},
		{
			name: "parse rule",
			s:    "-A foo --destination=192.168.178.2",
			r: Rule{
				Chain:       "foo",
				Destination: &DNSOrIPPair{Value: DNSOrIP{iP: parseCIDR("192.168.178.2")}},
			},
			err: nil,
		},
		{
			name: "parse rule with DNS name",
			s:    "-A foo --destination=example.com",
			r: Rule{
				Chain:       "foo",
				Destination: &DNSOrIPPair{Value: DNSOrIP{dNS: "example.com"}},
			},
			err: nil,
		},
		{
			name: "parse rule with not ending comment",
			s:    "-A foo ! --fragment -o=wg0 --in-interface=wlan-0  --destination=192.168.178.2  --protocol all  -j RETURN -m comment --comment \"this crazy\\",
			r: Rule{
				Chain:       "foo",
				Destination: &DNSOrIPPair{Value: DNSOrIP{iP: parseCIDR("192.168.178.2")}},
				Protocol: &StringPair{
					Value: "all",
				},
				InInterf: &StringPair{
					Value: "wlan-0",
				},
				OutInterf: &StringPair{
					Value: "wg0",
				},
				Fragment: &_false,
				Matches: []Match{
					{
						Type: "comment",
						Flags: map[string]Flag{
							"comment": {
								Values: []string{`this crazy\`},
							},
						},
					},
				},
				Jump: &Target{Name: "RETURN"},
			},
			err: nil,
		},
		{
			name: "parse rule with comment",
			s:    "-A foo ! --fragment -o=wg0 --in-interface=wlan-0  --destination=192.168.178.2   -m comment --comment \"this crazy\" --protocol all  -j RETURN",
			r: Rule{
				Chain:       "foo",
				Destination: &DNSOrIPPair{Value: DNSOrIP{iP: parseCIDR("192.168.178.2")}},
				Protocol: &StringPair{
					Value: "all",
				},
				InInterf: &StringPair{
					Value: "wlan-0",
				},
				OutInterf: &StringPair{
					Value: "wg0",
				},
				Fragment: &_false,
				Matches: []Match{
					{
						Type: "comment",
						Flags: map[string]Flag{
							"comment": {
								Values: []string{`this crazy`},
							},
						},
					},
				},
				Jump: &Target{Name: "RETURN"},
			},
			err: nil,
		},
		{
			name: "parse rule with weird comment",
			s:    "-A foo  -6 --ipv4 -g NOWHERE ! -f   -i wlan0 --destination=192.168.178.2  ! -p tcp  -m comment --comment \"--this-crazy\"",
			r: Rule{
				Chain:       "foo",
				Destination: &DNSOrIPPair{Value: DNSOrIP{iP: parseCIDR("192.168.178.2")}},
				IPv6:        true,
				IPv4:        true,
				Protocol: &StringPair{
					Not:   true,
					Value: "tcp",
				},
				InInterf: &StringPair{
					Value: "wlan0",
				},
				Fragment: &_false, // /BoolPair{Value: true, Not: true},
				Matches: []Match{
					{
						Type: "comment",
						Flags: map[string]Flag{
							"comment": {
								Values: []string{`--this-crazy`},
							},
						},
					},
				},
				Goto: &Target{Name: "NOWHERE"},
			},
			err: nil,
		},
		{
			name: "parse rule with quotes in comment",
			s:    "-A foo -4 --ipv6  -m tcp --dport 8080 --destination=192.168.178.2   -m comment --comment \"this \\\"crazy\\\"\"",
			r: Rule{
				Chain:       "foo",
				Destination: &DNSOrIPPair{Value: DNSOrIP{iP: parseCIDR("192.168.178.2")}},
				IPv4:        true,
				IPv6:        true,
				Matches: []Match{
					{
						Type: "tcp",
						Flags: map[string]Flag{
							"destination-port": {Values: []string{"8080"}},
						},
					},
					{
						Type: "comment",
						Flags: map[string]Flag{
							"comment": {
								Values: []string{`this \"crazy\"`},
							},
						},
					},
				},
			},
			err: nil,
		},
		{
			name: "parse rule with match all kind of flags",
			s:    "-A foo -4 --ipv6 --destination=192.168.178.2   -m comment --comment \"this \\\"crazy\\\"\" -m tcp ",
			r: Rule{
				Chain:       "foo",
				Destination: &DNSOrIPPair{Value: DNSOrIP{iP: parseCIDR("192.168.178.2")}},
				IPv4:        true,
				IPv6:        true,
				Matches: []Match{
					{
						Type: "comment",
						Flags: map[string]Flag{
							"comment": {
								Values: []string{`this \"crazy\"`},
							},
						},
					},
					{
						Type:  "tcp",
						Flags: map[string]Flag{},
					},
				},
			},
			err: nil,
		},
		{
			name: "parse rule with unknown flag",
			s:    "-A foo --destination=192.168.178.2   -m comment --comment \"this \\\"crazy\\\"\" --fantasy flag",
			err:  errors.New("failed to parse line, skipping rest \" flag\" of the line: unknown flag \"--fantasy\" found"),
		},
		{
			name: "parse rule with illegal flag",
			s:    "-A foo --destination=192.168.178.2 ! -j SOMEWHERE  -p fantasy  -m comment --comment \"this \\\"crazy\\\"\" --fantasy flag",
			err:  errors.New(`failed to parse line, skipping rest " SOMEWHERE  -p fantasy  -m comment --comment \"this \\\"crazy\\\"\" --fantasy flag" of the line: encountered unknown flag "-j", or flag can not be negated with "!"`),
		},
		{
			name: "parse rule with match expression tcp",
			s:    "-A foo  -m tcp --tcp-flags SYN,FIN ACK --sport 1010 --destination-port 8080:9000 -4",
			r: Rule{
				Chain: "foo",
				IPv4:  true,
				Matches: []Match{
					{
						Type: "tcp",
						Flags: map[string]Flag{
							"destination-port": {Values: []string{"8080:9000"}},
							"source-port":      {Values: []string{"1010"}},
							"tcp-flags":        {Values: []string{"SYN,FIN", "ACK"}},
						},
					},
				},
			},
			err: nil,
		},
		{
			name: "parse rule with match expression tcp and not",
			s:    "-A foo  -m tcp --tcp-flags SYN,FIN ACK --sport 1010  ! --dport=1000 ! -f",
			r: Rule{
				Chain:    "foo",
				Fragment: &_false,
				Matches: []Match{
					{
						Type: "tcp",
						Flags: map[string]Flag{
							"source-port": {Values: []string{"1010"}},
							"destination-port": {
								Values: []string{"1000"},
								Not:    true,
							},
							"tcp-flags": {Values: []string{"SYN,FIN", "ACK"}},
						},
					},
				},
			},
			err: nil,
		},
		{
			name: "parse rule with match expression tcp and a lot of flags and overwriting",
			s:    "-A foo  -m tcp --tcp-flags SYN,FIN ACK --sport 1010 ! --dport=1000:1010  --syn! --syn  ! --tcp-option 1  ! -f ",
			r: Rule{
				Chain:    "foo",
				Fragment: &_false,
				Matches: []Match{
					{
						Type: "tcp",
						Flags: map[string]Flag{
							"source-port": {Values: []string{"1010"}},
							"destination-port": {
								Values: []string{"1000:1010"},
								Not:    true,
							},
							"tcp-flags": {Values: []string{"SYN,FIN", "ACK"}},
							"tcp-option": {
								Not:    true,
								Values: []string{"1"},
							},
							"syn": {
								Not: true,
							},
						},
					},
				},
			},
			err: nil,
		},
		{
			name: "parse rule with match expression with all tcp flags",
			s:    "-A foo  -m tcp! --tcp-flags SYN,FIN ACK! --sport 1010  --dport=1000:1010  --syn   --tcp-option 1   -4 ",
			r: Rule{
				Chain: "foo",
				IPv4:  true,
				Matches: []Match{
					{
						Type: "tcp",
						Flags: map[string]Flag{
							"source-port": {
								Not:    true,
								Values: []string{"1010"},
							},
							"destination-port": {
								Values: []string{"1000:1010"},
							},
							"tcp-flags": {
								Not:    true,
								Values: []string{"SYN,FIN", "ACK"},
							},
							"tcp-option": {
								Values: []string{"1"},
							},
							"syn": {},
						},
					},
				},
			},
			err: nil,
		},
		{
			name: "parse rule with empty match expression tcp in the end",
			s:    "-A foo -m tcp -4",
			r: Rule{
				Chain: "foo",
				IPv4:  true,
				Matches: []Match{
					{
						Type:  "tcp",
						Flags: map[string]Flag{},
					},
				},
			},
			err: nil,
		},
		{
			name: "parse rule with jump target DNAT",
			s:    "-A foo  -m tcp! --tcp-flags SYN,FIN ACK! --sport 1010  --dport=1000:1010  --syn   --tcp-option 1   -4  -j DNAT --random --to-destination 192.168.1.1-192.168.1.2:80-81",
			r: Rule{
				Chain: "foo",
				IPv4:  true,
				Matches: []Match{
					{
						Type: "tcp",
						Flags: map[string]Flag{
							"source-port": {
								Not:    true,
								Values: []string{"1010"},
							},
							"destination-port": {
								Values: []string{"1000:1010"},
							},
							"tcp-flags": {
								Not:    true,
								Values: []string{"SYN,FIN", "ACK"},
							},
							"tcp-option": {
								Values: []string{"1"},
							},
							"syn": {},
						},
					},
				},
				Jump: &Target{
					Name: "DNAT",
					Flags: map[string]Flag{
						"random": {},
						"to-destination": {
							Values: []string{"192.168.1.1-192.168.1.2:80-81"},
						},
					},
				},
			},
			err: nil,
		},
		{
			name: "parse rule with multiport jump target DNAT",
			s:    "-A foo  -p tcp -m multiport --dports=25,143,465,587,993,4190 -4  -j DNAT --to-destination 192.168.1.1",
			r: Rule{
				Chain: "foo",
				IPv4:  true,
				Protocol: &StringPair{
					Not:   false,
					Value: "tcp",
				},
				Matches: []Match{
					{
						Type: "multiport",
						Flags: map[string]Flag{
							"destination-ports": {
								Values: []string{"25", "143", "465", "587", "993", "4190"},
							},
						},
					},
				},
				Jump: &Target{
					Name: "DNAT",
					Flags: map[string]Flag{
						"to-destination": {
							Values: []string{"192.168.1.1"},
						},
					},
				},
			},
			err: nil,
		},
		{
			name: "parse rule with jump target SNAT",
			s:    "-A foo -o eth0 -4 -j SNAT --to-source 192.168.1.1",
			r: Rule{
				Chain: "foo",
				IPv4:  true,
				OutInterf: &StringPair{
					Value: "eth0",
				},
				Jump: &Target{
					Name: "SNAT",
					Flags: map[string]Flag{
						"to-source": {
							Values: []string{"192.168.1.1"},
						},
					},
				},
			},
			err: nil,
		},
		{
			name: "parse rule with jump target fully-random SNAT",
			s:    "-A foo -o eth0 -4 -j SNAT --to-source 192.168.1.1 --random-fully",
			r: Rule{
				Chain: "foo",
				IPv4:  true,
				OutInterf: &StringPair{
					Value: "eth0",
				},
				Jump: &Target{
					Name: "SNAT",
					Flags: map[string]Flag{
						"to-source": {
							Values: []string{"192.168.1.1"},
						},
						"random-fully": {},
					},
				},
			},
			err: nil,
		},
		{
			name: "parse real rule made by kubernetes",
			s:    `-A KUBE-SERVICES -m comment --comment "kubernetes service nodeports; NOTE: this must be the last rule in this chain" -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS`,
			r: Rule{
				Chain: "KUBE-SERVICES",
				Matches: []Match{
					{
						Type: "comment",
						Flags: map[string]Flag{
							"comment": {Values: []string{`kubernetes service nodeports; NOTE: this must be the last rule in this chain`}},
						},
					},
					{
						Type: "addrtype",
						Flags: map[string]Flag{
							"dst-type": {
								Values: []string{"LOCAL"},
							},
						},
					},
				},
				Jump: &Target{
					Name: "KUBE-NODEPORTS",
				},
			},
			err: nil,
		},
		{
			name: "parse real rule made by kubernetes with udp match extension",
			s:    `-A KUBE-SERVICES -d 10.43.0.10/32 -p udp -m comment --comment "kube-system/kube-dns:dns cluster IP" -m udp --dport 53 -j KUBE-SVC-TCOU7JCQXEZGVUNU`,
			r: Rule{
				Chain: "KUBE-SERVICES",
				Destination: &DNSOrIPPair{
					Value: DNSOrIP{
						iP: parseCIDR("10.43.0.10/32"),
					},
				},
				Protocol: &StringPair{
					Value: "udp",
				},
				Matches: []Match{
					{
						Type: "comment",
						Flags: map[string]Flag{
							"comment": {Values: []string{`kube-system/kube-dns:dns cluster IP`}},
						},
					},
					{
						Type: "udp",
						Flags: map[string]Flag{
							"destination-port": {
								Values: []string{"53"},
							},
						},
					},
				},
				Jump: &Target{
					Name: "KUBE-SVC-TCOU7JCQXEZGVUNU",
				},
			},
			err: nil,
		},
		{
			name: "parse rule generated by kubernetes with MASQUERADE target",
			s:    `-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE --random-fully`,
			r: Rule{
				Chain: "KUBE-POSTROUTING",
				Matches: []Match{
					{
						Type: "comment",
						Flags: map[string]Flag{
							"comment": {Values: []string{`kubernetes service traffic requiring SNAT`}},
						},
					},
				},
				Jump: &Target{
					Name: "MASQUERADE",
					Flags: map[string]Flag{
						"random-fully": {},
					},
				},
			},
			err: nil,
		},
		{
			name: "parse rule with MASQUERADE target and all kinds of options",
			s:    `-A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -j MASQUERADE --random  --to-ports 200-1000 --random-fully`,
			r: Rule{
				Chain: "KUBE-POSTROUTING",
				Matches: []Match{
					{
						Type: "comment",
						Flags: map[string]Flag{
							"comment": {Values: []string{`kubernetes service traffic requiring SNAT`}},
						},
					},
				},
				Jump: &Target{
					Name: "MASQUERADE",
					Flags: map[string]Flag{
						"random-fully": {},
						"random":       {},
						"to-ports": {
							Values: []string{"200-1000"},
						},
					},
				},
			},
			err: nil,
		},
		{
			name: "parse rule with match expression statistic",
			s:    "-A foo ! -s 192.168.178.2 ! --dst 1.1.1.1 -m statistic --mode random --probability 0.50000000000 --every 10 --packet 5",
			r: Rule{
				Chain: "foo",
				Source: &DNSOrIPPair{
					Value: DNSOrIP{
						iP: parseCIDR("192.168.178.2"),
					},
					Not: true,
				},
				Destination: &DNSOrIPPair{Value: DNSOrIP{iP: parseCIDR("1.1.1.1")}, Not: true},
				Matches: []Match{{
					Type: "statistic",
					Flags: map[string]Flag{
						"mode": {
							Values: []string{`random`},
						},
						"probability": {
							Values: []string{`0.50000000000`},
						},
						"packet": {
							Values: []string{`5`},
						},
						"every": {
							Values: []string{`10`},
						},
					},
				}},
			},
			err: nil,
		},
		{
			name: "parse default rule",
			s:    ":hello-chain DROP [0:100]\n -A FORWARD -s 192.1.1.1",
			r: Policy{
				Chain:  "hello-chain",
				Action: "DROP",
				Counter: &Counter{
					packets: 0,
					bytes:   100,
				},
			},
			err: nil,
		},
		{
			name: "parse rule generated by docker",
			s:    "-A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER",
			r: Rule{
				Chain: "OUTPUT",
				Destination: &DNSOrIPPair{
					Not:   true,
					Value: DNSOrIP{iP: parseCIDR("127.0.0.0/8")},
				},
				Matches: []Match{
					{
						Type: "addrtype",
						Flags: map[string]Flag{
							"dst-type": {Values: []string{"LOCAL"}},
						},
					},
				},
				Jump: &Target{Name: "DOCKER"},
			},
			err: nil,
		},
		{
			name: "parse another rule generated by docker",
			s:    "-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE",
			r: Rule{
				Chain: "POSTROUTING",
				Source: &DNSOrIPPair{
					Value: DNSOrIP{iP: parseCIDR("172.17.0.0/16")},
				},
				OutInterf: &StringPair{
					Not:   true,
					Value: "docker0",
				},
				Jump: &Target{
					Name:  "MASQUERADE",
					Flags: map[string]Flag{},
				},
			},
			err: nil,
		},
		{
			name: "parse another rule generated by docker",
			s:    "-A POSTROUTING -s 172.18.0.0/16 ! -o br-21dc6a502417 -j MASQUERADE",
			r: Rule{
				Chain: "POSTROUTING",
				Source: &DNSOrIPPair{
					Value: DNSOrIP{iP: parseCIDR("172.18.0.0/16")},
				},
				OutInterf: &StringPair{
					Not:   true,
					Value: "br-21dc6a502417",
				},
				Jump: &Target{
					Name:  "MASQUERADE",
					Flags: map[string]Flag{},
				},
			},
			err: nil,
		},
		{
			name: "parse another rule generated by docker",
			s:    "-A POSTROUTING -s 172.18.0.3/32 -d 172.18.0.3/32 -p tcp -m tcp --dport 6443 -j MASQUERADE",
			r: Rule{
				Chain: "POSTROUTING",
				Source: &DNSOrIPPair{
					Value: DNSOrIP{iP: parseCIDR("172.18.0.3/32")},
				},
				Destination: &DNSOrIPPair{
					Value: DNSOrIP{iP: parseCIDR("172.18.0.3/32")},
				},
				Protocol: &StringPair{
					Value: "tcp",
				},
				Matches: []Match{
					{
						Type: "tcp",
						Flags: map[string]Flag{
							"destination-port": {
								Values: []string{"6443"},
							},
						},
					},
				},
				Jump: &Target{
					Name:  "MASQUERADE",
					Flags: map[string]Flag{},
				},
			},
			err: nil,
		},
		{
			name: "parse another rule generated by docker",
			s:    "-A DOCKER -i docker0 -j RETURN",
			r: Rule{
				Chain:    "DOCKER",
				InInterf: &StringPair{Value: "docker0"},
				Jump: &Target{
					Name: "RETURN",
				},
			},
			err: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := NewParser(strings.NewReader(tc.s))
			s, err := p.Parse()
			if !reflect.DeepEqual(tc.r, s) {
				t.Errorf("%d. %s: %q result mismatch:\n\texp=%v\n\tgot=%v\n\terr=%v", i, tc.name, tc.s, tc.r, s, err)
			} else if tc.err != err && tc.err.Error() != err.Error() {
				t.Errorf("%d. %s: %q error mismatch:\n\texp=%v\n\tgot=%v.", i, tc.name, tc.s, tc.err, err)
			}
		})
	}
}

func TestParser_ParseMore(t *testing.T) {
	for i, tc := range []struct {
		name string
		s    string
		r    []interface{}
	}{
		{
			name: "parse more lines",
			s: `# hello you.
				*hello you.
				:hello ACCEPT [10:100]
				-A foo ! --fragment -o=wg0 --in-interface=wlan-0  --destination=192.168.178.2   -m comment --comment "this crazy" --protocol all  -j RETURN
			blub`,
			r: []interface{}{
				Comment{Content: " hello you."},
				Header{Content: "hello you."},
				Policy{
					Chain:  "hello",
					Action: "ACCEPT",
					Counter: &Counter{
						packets: 10,
						bytes:   100,
					},
				},
				Rule{
					Chain:       "foo",
					Destination: &DNSOrIPPair{Value: DNSOrIP{iP: parseCIDR("192.168.178.2")}},
					Protocol: &StringPair{
						Value: "all",
					},
					InInterf: &StringPair{
						Value: "wlan-0",
					},
					OutInterf: &StringPair{
						Value: "wg0",
					},
					Fragment: &_false, // BoolPair{Value: true, Not: true},
					Matches: []Match{
						{
							Type: "comment",
							Flags: map[string]Flag{
								"comment": {
									Values: []string{`this crazy`},
								},
							},
						},
					},
					Jump: &Target{Name: "RETURN"},
				},
				errors.New("unexpected format of first token: blub, skipping rest \"\" of the line"),
				Rule{
					Chain: "KUBE-POSTROUTING",
					Matches: []Match{
						{
							Type: "comment",
							Flags: map[string]Flag{
								"comment": {Values: []string{"kubernetes service traffic requiring SNAT"}},
							},
						},
					},
					Jump: &Target{
						Name: "MASQUERADE",
						Flags: map[string]Flag{
							"random-fully": {},
							"random":       {},
							"to-ports": {
								Values: []string{"200-1000"},
							},
						},
					},
				},
			},
		},
		{
			name: "parse a bunch of rules generated by docker",
			s: `-A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER
-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
-A POSTROUTING -s 172.18.0.0/16 ! -o br-21dc6a502417 -j MASQUERADE
-A POSTROUTING -s 172.18.0.3/32 -d 172.18.0.3/32 -p tcp -m tcp --dport 6443 -j MASQUERADE
-A DOCKER -i docker0 -j RETURN
`,
			r: []interface{}{
				Rule{
					Chain: "OUTPUT",
					Destination: &DNSOrIPPair{
						Not:   true,
						Value: DNSOrIP{iP: parseCIDR("127.0.0.0/8")},
					},
					Matches: []Match{
						{
							Type: "addrtype",
							Flags: map[string]Flag{
								"dst-type": {Values: []string{"LOCAL"}},
							},
						},
					},
					Jump: &Target{Name: "DOCKER"},
				},
				Rule{
					Chain: "POSTROUTING",
					Source: &DNSOrIPPair{
						Value: DNSOrIP{iP: parseCIDR("172.17.0.0/16")},
					},
					OutInterf: &StringPair{
						Not:   true,
						Value: "docker0",
					},
					Jump: &Target{
						Name:  "MASQUERADE",
						Flags: map[string]Flag{},
					},
				},
				Rule{
					Chain: "POSTROUTING",
					Source: &DNSOrIPPair{
						Value: DNSOrIP{iP: parseCIDR("172.18.0.0/16")},
					},
					OutInterf: &StringPair{
						Not:   true,
						Value: "br-21dc6a502417",
					},
					Jump: &Target{
						Name:  "MASQUERADE",
						Flags: map[string]Flag{},
					},
				},
				Rule{
					Chain: "POSTROUTING",
					Source: &DNSOrIPPair{
						Value: DNSOrIP{iP: parseCIDR("172.18.0.3/32")},
					},
					Destination: &DNSOrIPPair{
						Value: DNSOrIP{iP: parseCIDR("172.18.0.3/32")},
					},
					Protocol: &StringPair{
						Value: "tcp",
					},
					Matches: []Match{
						{
							Type: "tcp",
							Flags: map[string]Flag{
								"destination-port": {
									Values: []string{"6443"},
								},
							},
						},
					},
					Jump: &Target{
						Name:  "MASQUERADE",
						Flags: map[string]Flag{},
					},
				},
				Rule{
					Chain:    "DOCKER",
					InInterf: &StringPair{Value: "docker0"},
					Jump: &Target{
						Name: "RETURN",
					},
				},
			},
		},
		{
			name: "Parse some rules from iptables -S",
			s: `-P INPUT ACCEPT
			-P FORWARD DROP
			-P OUTPUT ACCEPT
			-N DOCKER
			-N DOCKER-ISOLATION-STAGE-1
			-N DOCKER-ISOLATION-STAGE-2
			-N DOCKER-USER
			-A FORWARD -j DOCKER-USER
			-A FORWARD -j DOCKER-ISOLATION-STAGE-1`,
			r: []interface{}{
				Policy{
					UserDefined: &_false,
					Chain:       "INPUT",
					Action:      "ACCEPT",
				},
				Policy{
					UserDefined: &_false,
					Chain:       "FORWARD",
					Action:      "DROP",
				},
				Policy{
					UserDefined: &_false,
					Chain:       "OUTPUT",
					Action:      "ACCEPT",
				},
				Policy{
					UserDefined: &_true,
					Chain:       "DOCKER",
				},
				Policy{
					UserDefined: &_true,
					Chain:       "DOCKER-ISOLATION-STAGE-1",
				},
				Policy{
					UserDefined: &_true,
					Chain:       "DOCKER-ISOLATION-STAGE-2",
				},
				Policy{
					UserDefined: &_true,
					Chain:       "DOCKER-USER",
				},
				Rule{
					Chain: "FORWARD",
					Jump: &Target{
						Name: "DOCKER-USER",
					},
				},
				Rule{
					Chain: "FORWARD",
					Jump: &Target{
						Name: "DOCKER-ISOLATION-STAGE-1",
					},
				},
			},
		},
	} {
		p := NewParser(strings.NewReader(tc.s))
		j, k := 0, 0
		for s, err := p.Parse(); err != io.EOF; s, err = p.Parse() {
			if err == nil {
				if !reflect.DeepEqual(tc.r[j], s) {
					t.Errorf("%d. %s: %q result mismatch:\n\texp=%v\n\tgot=%v\n\terr=%v", i, tc.name, tc.s, tc.r[j], s, err)
				}
			} else {
				if !reflect.DeepEqual(tc.r[j], err) {
					t.Errorf("%d. %s: %q error mismatch:\n\texp=%v\n\tgot=%v.", i, tc.name, tc.s, tc.r[j], err)
				}
				k++
			}
			j++
		}
	}
}
