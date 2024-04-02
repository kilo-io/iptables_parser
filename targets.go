package iptables_parser

import (
	"errors"
	"fmt"
)

func (p *Parser) parseTarget(t *Target) (state, error) {
	tok, lit := p.scanIgnoreWhitespace()
	switch tok {
	case IDENT:
		break
	case NEWLINE:
		p.unscan(1)
		return sStart, nil
	default:
		return sError, fmt.Errorf("unexpected token %q, expected identifier", lit)
	}
	// Target is not part of a known target extension.
	// It could be a user defined chain or RETURN, etc.
	if _, ok := targetExtensions[lit]; !ok {
		t.Name = lit
		return sStart, nil
	}
	// Parse Target extensions:
	t.Flags = make(map[string]Flag)
	s := sStart
	var err error
	switch lit {
	case "DNAT":
		s, err = p.parseDNAT(&t.Flags)
	case "SNAT":
		s, err = p.parseSNAT(&t.Flags)
	case "MASQUERADE":
		s, err = p.parseMASQUERADE(&t.Flags)
	case "LOG":
		s, err = p.parseLOG(&t.Flags)
	default:
		s = sError
		err = fmt.Errorf("target %q is not implemented", lit)
	}
	if err == nil {
		t.Name = lit
	}
	return s, err
}

func (p *Parser) parseMASQUERADE(f *map[string]Flag) (state, error) {
	s := sStart
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
				default:
					// No more flags
					p.unscan(1)
					return sStart, nil
				}
			case sIF:
				switch {
				case lit == "--to-ports":
					str := ""
					for tok, lit := p.scanIgnoreWhitespace(); tok != EOF && tok != WS && tok != NOT; tok, lit = p.scan() {
						str += lit
					}
					(*f)["to-ports"] = Flag{
						Values: []string{str},
					}
					s = sStart
				case lit == "--random":
					(*f)["random"] = Flag{}
					s = sStart
				case lit == "--random-fully":
					(*f)["random-fully"] = Flag{}
					s = sStart
				default:
					// The end of the match statement is reached.
					p.unscan(1)
					return sStart, nil
				}

			default:
				return sStart, errors.New("unexpected error parsing match extension")
			}
		}
	}
	p.unscan(1) // unscan the last rune, so main parser can interprete it
	return sStart, nil
}

func (p *Parser) parseSNAT(f *map[string]Flag) (state, error) {
	s := sStart
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
				default:
					// No more flags
					p.unscan(1)
					return sStart, nil
				}
			case sIF:
				switch {
				case lit == "--to-source":
					str := ""
					for tok, lit := p.scanIgnoreWhitespace(); tok != EOF && tok != WS && tok != NOT && tok != NEWLINE; tok, lit = p.scan() {
						str += lit
					}
					p.unscan(1)
					(*f)["to-source"] = Flag{
						Values: []string{str},
					}
					s = sStart
				case lit == "--random":
					(*f)["random"] = Flag{}
					s = sStart
				case lit == "--random-fully":
					(*f)["random-fully"] = Flag{}
					s = sStart
				case lit == "--persistent":
					(*f)["persistent"] = Flag{}
					s = sStart
				default:
					// The end of the match statement is reached.
					p.unscan(1)
					return sStart, nil
				}

			default:
				return sStart, errors.New("unexpected error parsing match extension")
			}
		}
	}
	p.unscan(1) // unscan the last rune, so main parser can interprete it
	return sStart, nil
}

func (p *Parser) parseDNAT(f *map[string]Flag) (state, error) {
	s := sStart
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
				default:
					// No more flags
					p.unscan(1)
					return sStart, nil
				}
			case sIF:
				switch {
				case lit == "--to-destination":
					str := ""
					for tok, lit := p.scanIgnoreWhitespace(); tok != EOF && tok != WS && tok != NOT && tok != NEWLINE; tok, lit = p.scan() {
						str += lit
					}
					p.unscan(1)
					(*f)["to-destination"] = Flag{
						Values: []string{str},
					}
					s = sStart
				case lit == "--random":
					(*f)["random"] = Flag{}
					s = sStart
				case lit == "--persistent":
					(*f)["persistent"] = Flag{}
					s = sStart
				default:
					// The end of the match statement is reached.
					p.unscan(1)
					return sStart, nil
				}

			default:
				return sStart, errors.New("unexpected error parsing match extension")
			}
		}
	}
	p.unscan(1) // unscan the last rune, so main parser can interprete it
	return sStart, nil
}

func (p *Parser) parseLOG(f *map[string]Flag) (state, error) {
	s := sStart
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
				default:
					// No more flags
					p.unscan(1)
					return sStart, nil
				}
			case sIF:
				switch {
				case lit == "--log-prefix":
					_, lit := p.scanIgnoreWhitespace()
					(*f)["log-prefix"] = Flag{
						Values: []string{lit},
					}
					s = sStart
				case lit == "--log-level":
					_, lit := p.scanIgnoreWhitespace()
					(*f)["log-level"] = Flag{
						Values: []string{lit},
					}
					s = sStart
				case lit == "--log-tcp-sequence":
					(*f)["log-tcp-sequence"] = Flag{}
					s = sStart
				case lit == "--log-tcp-options":
					(*f)["log-tcp-options"] = Flag{}
					s = sStart
				case lit == "--log-ip-options":
					(*f)["log-ip-options"] = Flag{}
					s = sStart
				case lit == "--log-macdecode":
					(*f)["log-macdecode"] = Flag{}
					s = sStart
				case lit == "--log-uid":
					(*f)["log-uid"] = Flag{}
					s = sStart
				default:
					// The end of the match statement is reached.
					p.unscan(1)
					return sStart, nil
				}

			default:
				return sStart, errors.New("unexpected error parsing match extension")
			}
		}
	}
	p.unscan(1) // unscan the last rune, so main parser can interprete it
	return sStart, nil
}
