package ast

import (
	"ssh-client-parser/token"
)

type Node interface {
	TokenLiteral() string
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

type ConfigStatement struct {
	Name token.Token
	Value string
}

func (ls *ConfigStatement) statementNode() {}
func (ls *ConfigStatement) TokenLiteral() string {
	return ls.Name.Literal
}

