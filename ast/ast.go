package ast

import (
	"bytes"
	"ssh-client-parser/token"
)

var (
	_ Statement = (*HostStatement)(nil)
	_ Statement = (*BlockStatement)(nil)
	_ Statement = (*HostNameStatement)(nil)

	// _ Statement = (*MatchStatement)(nil)
)

type Node interface {
	TokenLiteral() string
	String() string
}

type Statement interface {
	Node
}

// Program
type Program struct {
	Statements []Statement
}
func (p *Program) TokenLiteral() string {
	if len(p.Statements) > 0 {
		return p.Statements[0].TokenLiteral()
	} else {
		return ""
	}
}
func (p *Program) String() string {
	var out bytes.Buffer

	for _, s := range p.Statements {
		out.WriteString(s.String())
	}

	return out.String()
}

type HostNameStatement struct {
	Token token.Token
	Value string
}
func (h HostNameStatement) TokenLiteral() string {
	return h.Token.Literal
}
func (h HostNameStatement) String() string {
	var out bytes.Buffer
	out.WriteString(h.Value)
	return out.String()
}

// BlockStatement anything after the 'Host' statement
type BlockStatement struct {
	Token token.Token
	Value string
	Statements []Statement
}
func (b *BlockStatement) TokenLiteral() string {
	return b.Token.Literal
}
func (b *BlockStatement) String() string {
	var out bytes.Buffer
	for _, s := range b.Statements {
		out.WriteString(s.String())
	}
	return out.String()
}

// MatchStatement statement
//type MatchStatement struct {
//	Token      token.Token // the Match token
//	Condition  string
//	Value      string
//	Statements []Statement
//}
//func (ms *MatchStatement) statementNode() {}
//func (ms *MatchStatement) TokenLiteral() string {
//	return ms.Token.Literal
//}
//func (ms *MatchStatement) String() string {
//	var out bytes.Buffer
//
//	out.WriteString(ms.Token.Literal)
//	out.WriteString(ms.Condition)
//	out.WriteString(ms.Value)
//
//	for _, s := range ms.Statements {
//		out.WriteString(s.String())
//	}
//
//	return out.String()
//}

// HostStatement statement
type HostStatement struct {
	Token      token.Token // the 'Host' token
	Value      string

	Statement *BlockStatement
}
func (ls *HostStatement) TokenLiteral() string {
	return ls.Token.Literal
}
func (ls *HostStatement) String() string {
	var out bytes.Buffer

	out.WriteString(ls.Token.Literal)
	out.WriteString(ls.Value)

	for _, s := range ls.Statement.Statements {
		out.WriteString(s.String())
	}

	return out.String()
}
