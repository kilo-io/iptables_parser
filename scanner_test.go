package iptables_parser

import (
	"fmt"
	"strings"
	"testing"
)

func TestScanner_Scan(t *testing.T) {
	for i, tc := range []struct {
		s   string
		tok Token
		lit string
	}{
		{s: "", tok: EOF, lit: ""},
		{s: `# `, tok: COMMENTLINE, lit: ` `},
		{s: `#`, tok: COMMENTLINE, lit: ""},
		{s: "-src", tok: FLAG, lit: "-src"},
		{s: "--src", tok: FLAG, lit: "--src"},
		{s: "-src=", tok: FLAG, lit: "-src"},
		{s: "   -src=", tok: WS, lit: "   "},
		{s: "--destination-port", tok: FLAG, lit: "--destination-port"},
		{s: "---destination-port", tok: FLAG, lit: "---destination-port"},
		{s: "  ", tok: WS, lit: "  "},
		{s: "\"hello my friend\" ", tok: COMMENT, lit: `hello my friend`},
		{s: `"hello 'my' friend" `, tok: COMMENT, lit: `hello 'my' friend`},
		{s: `"hello \"my\" friend" bla`, tok: COMMENT, lit: "hello \\\"my\\\" friend"},
		{s: `"hello \"my\" friend bla\`, tok: COMMENT, lit: "hello \\\"my\\\" friend bla\\"},
		{s: "hello friend", tok: IDENT, lit: "hello"},
		{s: "192.168.178.2/24", tok: IDENT, lit: "192.168.178.2/24"},
		{s: "2001:db8::/64", tok: IDENT, lit: "2001:db8::/64"},
		{s: "# 192.168.178.2/24", tok: COMMENTLINE, lit: " 192.168.178.2/24"},
		{s: "I_test_rule-something", tok: IDENT, lit: "I_test_rule-something"},
	} {
		t.Run(fmt.Sprintf("%d. %q", i, tc.s), func(t *testing.T) {
			s := newScanner(strings.NewReader(tc.s))
			tok, lit := s.scan()
			if tc.tok != tok {
				t.Errorf("%q token mismatch: exp=%q got=%q <%q>", tc.s, tc.tok, tok, lit)
			} else if tc.lit != lit {
				t.Errorf("%q literal mismatch: exp=%q got=%q", tc.s, tc.lit, lit)
			}
		})
	}
}

func TestScanner_readLine(t *testing.T) {
	for i, tc := range []struct {
		s string
		r string
	}{
		{
			s: "hello you\nasdf",
			r: "hello you",
		},
		{
			s: "hello",
			r: "hello",
		},
	} {
		s := newScanner(strings.NewReader(tc.s))
		str := s.scanLine()
		if tc.r != str {
			t.Errorf("%d. mismatch: exp=%q got=%q", i, tc.r, str)
		}
	}
}
