package ast

import (
	"bytes"

	"github.com/calvernaz/scp/token"
)

var (
	_ Statement = (*HostStatement)(nil)
	_ Statement = (*BlockStatement)(nil)
	_ Statement = (*HostNameStatement)(nil)
	_ Statement = (*IdentityFileStatement)(nil)
	_ Statement = (*UserStatement)(nil)
	_ Statement = (*PortStatement)(nil)
	_ Statement = (*UseKeyStatement)(nil)
	_ Statement = (*AddKeysToAgentStatement)(nil)
	_ Statement = (*LocalForwardStatement)(nil)
	// _ Statement = (*MatchStatement)(nil)
)

type Node interface {
	TokenLiteral() string
	String() string
}

type Statement interface {
	Node
}

// SshConfig data structure holds Host and Match blocks.
type SshConfig struct {
	Statements []Statement
}

func (p *SshConfig) TokenLiteral() string {
	if len(p.Statements) > 0 {
		return p.Statements[0].TokenLiteral()
	} else {
		return ""
	}
}
func (p *SshConfig) String() string {
	var out bytes.Buffer

	for _, s := range p.Statements {
		out.WriteString(s.String())
	}

	return out.String()
}

// HostStatement statement
type HostStatement struct {
	Token token.Token // the 'Host' token
	Value string

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

// BlockStatement anything after the 'Host' statement
type BlockStatement struct {
	Statements []Statement
}

func (b *BlockStatement) TokenLiteral() string {
	return ""
}
func (b *BlockStatement) String() string {
	var out bytes.Buffer
	for _, s := range b.Statements {
		out.WriteString(s.String())
	}
	return out.String()
}

// HostNameStatement hostname inside the Host block
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

// IdentityFile
type IdentityFileStatement struct {
	Token token.Token
	Value string
}

func (i *IdentityFileStatement) TokenLiteral() string {
	return i.Token.Literal
}
func (i IdentityFileStatement) String() string {
	var out bytes.Buffer
	out.WriteString(i.Value)
	return out.String()
}

// User
type UserStatement struct {
	Token token.Token
	Value string
}

func (u UserStatement) TokenLiteral() string {
	return u.Token.Literal
}
func (u UserStatement) String() string {
	var out bytes.Buffer
	out.WriteString(u.Value)
	return out.String()
}

// Port
type PortStatement struct {
	Token token.Token
	Value string
}

func (u PortStatement) TokenLiteral() string {
	return u.Token.Literal
}
func (u PortStatement) String() string {
	var out bytes.Buffer
	out.WriteString(u.Value)
	return out.String()
}

// UseKeyStatement
type UseKeyStatement struct {
	Token token.Token
	Value string
}

func (u UseKeyStatement) TokenLiteral() string {
	return u.Token.Literal
}

func (u UseKeyStatement) String() string {
	var out bytes.Buffer
	out.WriteString(u.Value)
	return out.String()
}

type AddKeysToAgentStatement struct {
	Token token.Token
	Value string
}

func (a AddKeysToAgentStatement) TokenLiteral() string {
	return a.Token.Literal
}

func (a AddKeysToAgentStatement) String() string {
	var out bytes.Buffer
	out.WriteString(a.Value)
	return out.String()
}

type LocalForwardStatement struct {
	Token token.Token
	Value string
}

func (l LocalForwardStatement) TokenLiteral() string {
	return l.Token.Literal
}

func (l LocalForwardStatement) String() string {
	var out bytes.Buffer
	out.WriteString(l.Value)
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
