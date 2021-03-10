package iptables_parser

import (
	"bufio"
	"bytes"
	"io"
)

type scanner struct {
	r *bufio.Reader
}

// eof represents a marker rune for the end of the reader.
const eof = rune(0)

func newScanner(r io.Reader) *scanner {
	return &scanner{r: bufio.NewReader(r)}
}

// scan returns the next token and literal value.
func (s *scanner) scan() (tok Token, lit string) {
	// Read the next rune.
	ch := s.read()
	switch {
	case isWhitespace(ch):
		s.unread()
		return s.scanWhitespace()
	case isLetter(ch) || isDigit(ch):
		s.unread()
		return s.scanIdent()
	}

	// Otherwise read the individual character.
	switch ch {
	case '-':
		s.unread()
		return s.scanFlag()
	case '"':
		s.unread()
		return s.scanDQuoted()
	case '#':
		return COMMENTLINE, s.scanLine()
	case '[':
		s.unread()
		return COUNTER, s.scanCounter()
	case '*':
		return HEADER, s.scanLine()
	case ':':
		return COLON, ":"
	case '!':
		return NOT, "!"
	case ',':
		return COMMA, ","
	case '\n':
		return NEWLINE, "\n"
	case eof:
		return EOF, ""
	}
	return ILLEGAL, string(ch)
}

func (s *scanner) scanCounter() string {
	var buf bytes.Buffer

	for {
		if ch := s.read(); ch == eof || ch == '\n' {
			break
		} else if ch == ']' {
			_, _ = buf.WriteRune(ch)
			break
		} else {
			_, _ = buf.WriteRune(ch)
		}
	}
	return buf.String()
}

func (s *scanner) scanLine() string {
	var buf bytes.Buffer
	for {
		if ch := s.read(); ch == eof {
			break
		} else if ch == '\n' {
			break
		} else {
			if _, err := buf.WriteRune(ch); err != nil {
				panic(err.Error())
			}
		}
	}
	return buf.String()
}

// scanDQuoted scans everything from the first double quotation mark until the next one.
// Quotes masked with the backslash are ignored.
// The returned literal does not return the wraping quotation marks.
// If there is no closing quotation mark, scanDQuoted will scan everything
// until the end of file.
func (s *scanner) scanDQuoted() (Token, string) {
	if ch := s.read(); ch != '"' {
		panic("Unexpected rune: " + string(ch) + ", expected \"\n")
	}

	var buf bytes.Buffer
	var err error
	for err == nil {
		if ch := s.read(); ch == eof {
			break
		} else if ch == '"' {
			break
		} else if ch == '\\' {
			_, err = buf.WriteRune(ch)
			if ch := s.read(); ch != eof {
				_, err = buf.WriteRune(ch)
			} else {
				break
			}
		} else {
			_, err = buf.WriteRune(ch)
		}
	}
	if err != nil {
		panic(err.Error())
	}

	return COMMENT, buf.String()
}

// scanWhitespace consumes the current rune and all contiguous whitespace.
func (s *scanner) scanWhitespace() (tok Token, lit string) {
	// Create a buffer and read the current character into it.
	var buf bytes.Buffer
	buf.WriteRune(s.read())

	// Read every subsequent whitespace character into the buffer.
	// Non-whitespace characters and EOF will cause the loop to exit.
	for {
		if ch := s.read(); ch == eof {
			break
		} else if !isWhitespace(ch) {
			s.unread()
			break
		} else {
			buf.WriteRune(ch)
		}
	}

	return WS, buf.String()
}

// scanFlag reads a flag (--flag, -f -flag=) and returns after reaching the "=" or whitespace.
// Flags may consist of letters, digits, "-" and "_".
// The hole flag is returned as the literal, including leading dashes, exluding the trailing "=".
func (s *scanner) scanFlag() (tok Token, lit string) {
	// Create a buffer and read the current character into it.
	var buf bytes.Buffer
	// buf.WriteRune(s.read())
	for {
		if ch := s.read(); ch == eof {
			break
		} else if ch == '=' {
			break
		} else if !isLetter(ch) && !isDigit(ch) && ch != '_' && ch != '-' {
			s.unread()
			break
		} else {
			if _, err := buf.WriteRune(ch); err != nil {
				panic("not able to write to buffer")
			}

		}
	}

	return FLAG, buf.String()
}

// scanIdent consumes the current rune and all contiguous ident runes.
func (s *scanner) scanIdent() (tok Token, lit string) {
	// Create a buffer and read the current character into it.
	var buf bytes.Buffer
	buf.WriteRune(s.read())

	// Read every subsequent ident character into the buffer.
	// Non-ident characters and EOF will cause the loop to exit.
	for {
		if ch := s.read(); ch == eof {
			break
		} else if !isLetter(ch) && !isDigit(ch) && !isMisc(ch) {
			s.unread()
			break
		} else {
			_, _ = buf.WriteRune(ch)
		}
	}

	return IDENT, buf.String()
}

// read reads the next rune from the buffered reader.
// Returns the rune(0) if an error occurs.
func (s *scanner) read() rune {
	ch, _, err := s.r.ReadRune()
	if err != nil {
		return eof
	}
	return ch
}

// unread places the previously read rune back on the reader.
func (s *scanner) unread() { _ = s.r.UnreadRune() }

// isWhitespace returns true if the rune is a space, tab, or newline.
func isWhitespace(ch rune) bool { return ch == ' ' || ch == '\t' }

// isLetter returns true if the rune is a letter.
func isLetter(ch rune) bool { return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') }

// isDigit returns true if the rune is a digit.
func isDigit(ch rune) bool { return (ch >= '0' && ch <= '9') }

func isMisc(ch rune) bool { return (ch == '.' || ch == '/' || ch == '-') }
