package validate_dns

import (
	"testing"
)

func TestDns_DNSLabel(t *testing.T) {
	for i, tc := range []struct {
		s string
		r bool
	}{
		{
			s: "hello-de",
			r: true,
		},
		{
			s: "",
			r: false,
		},
		{
			s: "-hello",
			r: false,
		},
		{
			s: "de",
			r: true,
		},
	} {
		if IsDNSLabel(tc.s) != tc.r {
			t.Errorf("test case %d:\n\tinput: %s\n\texp= \"%v\"\n\tgot= \"%v\"", i, tc.s, tc.r, !tc.r)
		}
	}
}

func TestDns_DNS(t *testing.T) {
	for i, tc := range []struct {
		s string
		r bool
	}{
		{
			s: "hello.de",
			r: true,
		},
		{
			s: "hello.you.de",
			r: true,
		},
		{
			s: "thatain-.com",
			r: false,
		},
		{
			s: "hellode",
			r: false,
		},
	} {
		if IsDNS(tc.s) != tc.r {
			t.Errorf("test case %d:\n\tinput: %s\n\texp= \"%v\"\n\tgot= \"%v\"", i, tc.s, tc.r, !tc.r)
		}
	}
}
