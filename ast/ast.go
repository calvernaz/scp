package ast

import (
	"bytes"
	"ssh-client-parser/token"
)

type Node interface {
	TokenLiteral() string
	String() string
}

type Statement interface {
	Node
	statementNode()
}

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

type MatchStatement struct {
	Token      token.Token // the Match token
	Value      string
	Statements []Statement
}

func (ms *MatchStatement) statementNode() {}
func (ms *MatchStatement) TokenLiteral() string {
	return ms.Token.Literal
}

type HostStatement struct {
	Token      token.Token // the Host token
	Value      string
	Statements []Statement
}

func (ls *HostStatement) statementNode() {}
func (ls *HostStatement) TokenLiteral() string {
	return ls.Token.Literal
}

func (ls *HostStatement) String() string {
	var out bytes.Buffer

	out.WriteString(ls.Token.Literal)
	out.WriteString(ls.Value)

	for _, s := range ls.Statements {
		out.WriteString(s.String())
	}

	return out.String()
}
