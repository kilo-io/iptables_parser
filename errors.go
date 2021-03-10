package iptables_parser

import (
	"errors"
)

type ParseError struct {
	s string
}

func NewParseError(s string) error {
	return &ParseError{s: s}
}

func (e *ParseError) Error() string {
	return e.s
}

var ErrEOF = errors.New("end of file")
