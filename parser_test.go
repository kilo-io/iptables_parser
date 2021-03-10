package iptables_parser

import (
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
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
			err:  ErrEOF,
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
			r: Default{
				Chain:  "hello",
				Action: "ACCEPT",
				Counter: Counter{
					packets: 10,
					bytes:   100,
				}},
			err: nil,
		},
		{
			name: "parse default rule",
			s:    ":hello-chain DROP [0:100]",
			r: Default{
				Chain:  "hello-chain",
				Action: "DROP",
				Counter: Counter{
					packets: 0,
					bytes:   100,
				}},
			err: nil,
		},
		{
			name: "parse rule",
			s:    "-A foo ! -s 192.168.178.2 ! --dst 1.1.1.1",
			r: Rule{
				Chain: "foo",
				src: DNSOrIPPair{value: DNSOrIP{
					iP: parseCIDR("192.168.178.2"),
				},
					not: true},
				dest: DNSOrIPPair{value: DNSOrIP{iP: parseCIDR("1.1.1.1")}, not: true},
			},
			err: nil,
		},
		{
			name: "parse rule",
			s:    "-A foo --destination=192.168.178.2",
			r: Rule{
				Chain: "foo",
				dest:  DNSOrIPPair{value: DNSOrIP{iP: parseCIDR("192.168.178.2")}},
			},
			err: nil,
		},
		{
			name: "parse rule with comment",
			s:    "-A foo ! --fragment -o=wg0 --in-interface=wlan-0  --destination=192.168.178.2   -m comment --comment \"this crazy\" --protocol all  -j RETURN",
			r: Rule{
				Chain: "foo",
				dest:  DNSOrIPPair{value: DNSOrIP{iP: parseCIDR("192.168.178.2")}},
				Protocol: StringPair{
					Value: "all",
				},
				InInterf: StringPair{
					Value: "wlan-0",
				},
				OutInterf: StringPair{
					Value: "wg0",
				},
				Fragment: BoolPair{Value: true, Not: true},
				Matches: []Match{
					{
						Type: "comment",
						Flags: map[string]Flag{
							"comment": Flag{
								Values: []string{"this crazy"},
							},
						},
					},
				},
				Jump: Target{Name: "RETURN"},
			},
			err: nil,
		},
		{
			name: "parse rule with weird comment",
			s:    "-A foo  -6 --ipv4 -g NOWHERE ! -f   -i wlan0 --destination=192.168.178.2  ! -p tcp  -m comment --comment \"--this-crazy\"",
			r: Rule{
				Chain: "foo",
				dest:  DNSOrIPPair{value: DNSOrIP{iP: parseCIDR("192.168.178.2")}},
				IPv6:  true,
				IPv4:  true,
				Protocol: StringPair{
					Not:   true,
					Value: "tcp",
				},
				InInterf: StringPair{
					Value: "wlan0",
				},
				Fragment: BoolPair{Value: true, Not: true},
				Matches: []Match{
					{
						Type: "comment",
						Flags: map[string]Flag{
							"comment": Flag{
								Values: []string{"--this-crazy"},
							},
						},
					},
				},
				Goto: Target{Name: "NOWHERE"},
			},
			err: nil,
		},
		{
			name: "parse rule with quotes in comment",
			s:    "-A foo -4 --ipv6  -m tcp --dport 8080 --destination=192.168.178.2   -m comment --comment \"this \\\"crazy\\\"\"",
			r: Rule{
				Chain: "foo",
				dest:  DNSOrIPPair{value: DNSOrIP{iP: parseCIDR("192.168.178.2")}},
				IPv4:  true,
				IPv6:  true,
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
							"comment": Flag{
								Values: []string{"this \\\"crazy\\\""},
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
				Chain: "foo",
				dest:  DNSOrIPPair{value: DNSOrIP{iP: parseCIDR("192.168.178.2")}},
				IPv4:  true,
				IPv6:  true,
				Matches: []Match{
					{
						Type: "comment",
						Flags: map[string]Flag{
							"comment": Flag{
								Values: []string{"this \\\"crazy\\\""},
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
			err:  errors.New("failed to parse line, skipping rest \"\" of the line: unknown flag \"--fantasy\" found"),
		},
		{
			name: "parse rule with illegal flag",
			s:    "-A foo --destination=192.168.178.2 ! -j SOMEWHERE  -p fantasy  -m comment --comment \"this \\\"crazy\\\"\" --fantasy flag",
			err:  errors.New(`failed to parse line, skipping rest "  -p fantasy  -m comment --comment \"this \\\"crazy\\\"\" --fantasy flag" of the line: encountered unknown flag "-j", or flag can not be negated with "!"`),
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
							"destination-port": Flag{Values: []string{"8080:9000"}},
							"source-port":      Flag{Values: []string{"1010"}},
							"tcp-flags":        Flag{Values: []string{"SYN,FIN", "ACK"}},
						},
					},
				},
			},
			err: nil,
		},
		{
			name: "parse rule with match expression tcp and a not",
			s:    "-A foo  -m tcp --tcp-flags SYN,FIN ACK --sport 1010  ! --dport=1000 ! -4",
			r: Rule{
				Chain: "foo",
				IPv4:  false,
				Matches: []Match{
					{
						Type: "tcp",
						Flags: map[string]Flag{
							"source-port": Flag{Values: []string{"1010"}},
							"destination-port": Flag{
								Values: []string{"1000"},
								Not:    true,
							},
							"tcp-flags": Flag{Values: []string{"SYN,FIN", "ACK"}},
						},
					},
				},
			},
			err: nil,
		},
		{
			name: "parse rule with match expression tcp and a lot of flags and overwriting",
			s:    "-A foo  -m tcp --tcp-flags SYN,FIN ACK --sport 1010 ! --dport=1000:1010  --syn! --syn  ! --tcp-option 1  ! -4 ",
			r: Rule{
				Chain: "foo",
				IPv4:  false,
				Matches: []Match{
					{
						Type: "tcp",
						Flags: map[string]Flag{
							"source-port": Flag{Values: []string{"1010"}},
							"destination-port": Flag{
								Values: []string{"1000:1010"},
								Not:    true,
							},
							"tcp-flags": Flag{Values: []string{"SYN,FIN", "ACK"}},
							"tcp-option": Flag{
								Not:    true,
								Values: []string{"1"},
							},
							"syn": Flag{
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
							"source-port": Flag{
								Not:    true,
								Values: []string{"1010"},
							},
							"destination-port": Flag{
								Values: []string{"1000:1010"},
							},
							"tcp-flags": Flag{
								Not:    true,
								Values: []string{"SYN,FIN", "ACK"},
							},
							"tcp-option": Flag{
								Values: []string{"1"},
							},
							"syn": Flag{},
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
							"source-port": Flag{
								Not:    true,
								Values: []string{"1010"},
							},
							"destination-port": Flag{
								Values: []string{"1000:1010"},
							},
							"tcp-flags": Flag{
								Not:    true,
								Values: []string{"SYN,FIN", "ACK"},
							},
							"tcp-option": Flag{
								Values: []string{"1"},
							},
							"syn": Flag{},
						},
					},
				},
				Jump: Target{
					Name: "DNAT",
					Flags: map[string]Flag{
						"random": Flag{},
						"to-destination": Flag{
							Values: []string{"192.168.1.1-192.168.1.2:80-81"},
						},
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
							"comment": Flag{Values: []string{"kubernetes service nodeports; NOTE: this must be the last rule in this chain"}},
						},
					},
					{
						Type: "addrtype",
						Flags: map[string]Flag{
							"dst-type": Flag{
								Values: []string{"LOCAL"},
							},
						},
					},
				},
				Jump: Target{
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
				dest: DNSOrIPPair{
					value: DNSOrIP{
						iP: parseCIDR("10.43.0.10/32"),
					},
				},

				Protocol: StringPair{
					Value: "udp",
				},
				Matches: []Match{
					{
						Type: "comment",
						Flags: map[string]Flag{
							"comment": Flag{Values: []string{"kube-system/kube-dns:dns cluster IP"}},
						},
					},
					{
						Type: "udp",
						Flags: map[string]Flag{
							"destination-port": Flag{
								Values: []string{"53"},
							},
						},
					},
				},
				Jump: Target{
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
							"comment": Flag{Values: []string{"kubernetes service traffic requiring SNAT"}},
						},
					},
				},
				Jump: Target{
					Name: "MASQUERADE",
					Flags: map[string]Flag{
						"random-fully": Flag{},
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
							"comment": Flag{Values: []string{"kubernetes service traffic requiring SNAT"}},
						},
					},
				},
				Jump: Target{
					Name: "MASQUERADE",
					Flags: map[string]Flag{
						"random-fully": Flag{},
						"random":       Flag{},
						"to-ports": Flag{
							Values: []string{"200-1000"},
						},
					},
				},
			},
			err: nil,
		},
		{
			name: "parse default rule",
			s:    ":hello-chain DROP [0:100]\n -A FORWARD -s 192.1.1.1",
			r: Default{
				Chain:  "hello-chain",
				Action: "DROP",
				Counter: Counter{
					packets: 0,
					bytes:   100,
				}},
			err: nil,
		},
		{
			name: "parse rule generated by docker",
			s:    "-A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER",
			r: Rule{
				Chain: "OUTPUT",
				dest: DNSOrIPPair{
					not:   true,
					value: DNSOrIP{iP: parseCIDR("127.0.0.0/8")},
				},
				Matches: []Match{
					{
						Type: "addrtype",
						Flags: map[string]Flag{
							"dst-type": Flag{Values: []string{"LOCAL"}},
						},
					},
				},
				Jump: Target{Name: "DOCKER"},
			},
			err: nil,
		},
		{
			name: "parse another rule generated by docker",
			s:    "-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE",
			r: Rule{
				Chain: "POSTROUTING",
				src: DNSOrIPPair{
					value: DNSOrIP{iP: parseCIDR("172.17.0.0/16")},
				},
				OutInterf: StringPair{
					Not:   true,
					Value: "docker0",
				},
				Jump: Target{
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
				src: DNSOrIPPair{
					value: DNSOrIP{iP: parseCIDR("172.18.0.0/16")},
				},
				OutInterf: StringPair{
					Not:   true,
					Value: "br-21dc6a502417",
				},
				Jump: Target{
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
				src: DNSOrIPPair{
					value: DNSOrIP{iP: parseCIDR("172.18.0.3/32")},
				},
				dest: DNSOrIPPair{
					value: DNSOrIP{iP: parseCIDR("172.18.0.3/32")},
				},
				Protocol: StringPair{
					Value: "tcp",
				},
				Matches: []Match{
					{
						Type: "tcp",
						Flags: map[string]Flag{
							"destination-port": Flag{
								Values: []string{"6443"},
							},
						},
					},
				},
				Jump: Target{
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
				InInterf: StringPair{Value: "docker0"},
				Jump: Target{
					Name: "RETURN",
				},
			},
			err: nil,
		},
	} {
		p := NewParser(strings.NewReader(tc.s))
		s, err := p.Parse()
		if !reflect.DeepEqual(tc.r, s) {
			t.Errorf("%d. %s: %q result mismatch:\n\texp=%v\n\tgot=%v\n\terr=%v", i, tc.name, tc.s, tc.r, s, err)
		} else if tc.err != err && tc.err.Error() != err.Error() {
			t.Errorf("%d. %s: %q error mismatch:\n\texp=%v\n\tgot=%v.", i, tc.name, tc.s, tc.err, err)
		}
	}
}

func TestParser_ParseMore(t *testing.T) {
	for i, tc := range []struct {
		name string
		s    string
		r    []Line
	}{
		{
			name: "parse more lines",
			s: `# hello you.
				*hello you.
				:hello ACCEPT [10:100]
				-A foo ! --fragment -o=wg0 --in-interface=wlan-0  --destination=192.168.178.2   -m comment --comment "this crazy" --protocol all  -j RETURN
			blub`,
			r: []Line{
				Comment{Content: " hello you."},
				Header{Content: "hello you."},
				Default{
					Chain:  "hello",
					Action: "ACCEPT",
					Counter: Counter{
						packets: 10,
						bytes:   100,
					}},
				Rule{
					Chain: "foo",
					dest:  DNSOrIPPair{value: DNSOrIP{iP: parseCIDR("192.168.178.2")}},
					Protocol: StringPair{
						Value: "all",
					},
					InInterf: StringPair{
						Value: "wlan-0",
					},
					OutInterf: StringPair{
						Value: "wg0",
					},
					Fragment: BoolPair{Value: true, Not: true},
					Matches: []Match{
						{
							Type: "comment",
							Flags: map[string]Flag{
								"comment": Flag{
									Values: []string{"this crazy"},
								},
							},
						},
					},
					Jump: Target{Name: "RETURN"},
				},
				NewParseError("unexpected format of first token: blub, skipping rest \"\" of the line"),
				Rule{
					Chain: "KUBE-POSTROUTING",
					Matches: []Match{
						{
							Type: "comment",
							Flags: map[string]Flag{
								"comment": Flag{Values: []string{"kubernetes service traffic requiring SNAT"}},
							},
						},
					},
					Jump: Target{
						Name: "MASQUERADE",
						Flags: map[string]Flag{
							"random-fully": Flag{},
							"random":       Flag{},
							"to-ports": Flag{
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
			r: []Line{
				Rule{
					Chain: "OUTPUT",
					dest: DNSOrIPPair{
						not:   true,
						value: DNSOrIP{iP: parseCIDR("127.0.0.0/8")},
					},
					Matches: []Match{
						{
							Type: "addrtype",
							Flags: map[string]Flag{
								"dst-type": Flag{Values: []string{"LOCAL"}},
							},
						},
					},
					Jump: Target{Name: "DOCKER"},
				},
				Rule{
					Chain: "POSTROUTING",
					src: DNSOrIPPair{
						value: DNSOrIP{iP: parseCIDR("172.17.0.0/16")},
					},
					OutInterf: StringPair{
						Not:   true,
						Value: "docker0",
					},
					Jump: Target{
						Name:  "MASQUERADE",
						Flags: map[string]Flag{},
					},
				},
				Rule{
					Chain: "POSTROUTING",
					src: DNSOrIPPair{
						value: DNSOrIP{iP: parseCIDR("172.18.0.0/16")},
					},
					OutInterf: StringPair{
						Not:   true,
						Value: "br-21dc6a502417",
					},
					Jump: Target{
						Name:  "MASQUERADE",
						Flags: map[string]Flag{},
					},
				},
				Rule{
					Chain: "POSTROUTING",
					src: DNSOrIPPair{
						value: DNSOrIP{iP: parseCIDR("172.18.0.3/32")},
					},
					dest: DNSOrIPPair{
						value: DNSOrIP{iP: parseCIDR("172.18.0.3/32")},
					},
					Protocol: StringPair{
						Value: "tcp",
					},
					Matches: []Match{
						{
							Type: "tcp",
							Flags: map[string]Flag{
								"destination-port": Flag{
									Values: []string{"6443"},
								},
							},
						},
					},
					Jump: Target{
						Name:  "MASQUERADE",
						Flags: map[string]Flag{},
					},
				},
				Rule{
					Chain:    "DOCKER",
					InInterf: StringPair{Value: "docker0"},
					Jump: Target{
						Name: "RETURN",
					},
				},
			},
		},
	} {
		p := NewParser(strings.NewReader(tc.s))
		j, k := 0, 0
		for s, err := p.Parse(); err != ErrEOF; s, err = p.Parse() {
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
