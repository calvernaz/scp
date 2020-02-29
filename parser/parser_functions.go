package parser

import (
	"github.com/calvernaz/scp/ast"
	"github.com/calvernaz/scp/token"
)

func (p *Parser) parseHostnameStatement() ast.Statement {
	stmt := &ast.HostNameStatement{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseIdentityFileStatement() ast.Statement {
	stmt := &ast.IdentityFileStatement{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseUserStatement() ast.Statement {
	stmt := &ast.UserStatement{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parsePortStatement() ast.Statement {
	stmt := &ast.PortStatement{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseUseKeyStatement() ast.Statement {
	stmt := &ast.UseKeyStatement{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseAddKeysToAgentStatement() ast.Statement {
	stmt := &ast.AddKeysToAgentStatement{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseLocalForwardStatement() ast.Statement {
	stmt := &ast.LocalForwardStatement{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.INT) {
		stmt.Value = p.curToken.Literal
	}

	p.nextToken()

	if p.curTokenIs(token.INT) {
		stmt.Value = stmt.Value + " " + p.curToken.Literal
	}
	return stmt
}
