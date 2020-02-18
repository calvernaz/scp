package parser

import (
	"ssh-client-parser/ast"
	"ssh-client-parser/token"
)

func (p *Parser) parseHostnameStatement() ast.Statement {
	stmt := &ast.HostNameStatement{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

