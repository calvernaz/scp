package parser

import (
	"ssh-client-parser/ast"
	"ssh-client-parser/lexer"
	"ssh-client-parser/token"
)

type Parser struct {
	l *lexer.Lexer

	curToken  token.Token
	peekToken token.Token
}

func New(l *lexer.Lexer) *Parser {
	p := &Parser{l: l}

	// Read two tokens, so curToken and peekToken are both set
	p.nextToken()
	p.nextToken()

	return p
}

func (p *Parser) nextToken() {
	p.curToken = p.peekToken
	p.peekToken = p.l.NextToken()
}

func (p *Parser) curTokenIs(t token.TokenType) bool {
	return p.curToken.Type == t
}

func (p *Parser) peekTokenIs(t token.TokenType) bool {
	return p.peekToken.Type == t
}

func (p *Parser) expectPeek(t token.TokenType) bool {
	if p.peekTokenIs(t) {
		p.nextToken()
		return true
	} else {
		return false
	}
}

func (p *Parser) ParseProgram() *ast.Program {
	program := &ast.Program{}
	program.Statements = []ast.Statement{}
	for p.curToken.Type != token.EOF {
		stmt := p.parseStatement()
		if stmt != nil {
			program.Statements = append(program.Statements, stmt)
		}
		p.nextToken()
	}
	return program
}

func (p *Parser) parseStatement() ast.Statement {
	switch p.curToken.Type {
	case token.HOST:
		return p.parseHostStatement()
	case token.MATCH:
		return p.parseMatchStatement()
	default:
		return nil
	}
}

func (p *Parser) parseHostStatement() *ast.HostStatement {
	stmt := &ast.HostStatement{Token: p.curToken}
	return stmt
}

func (p *Parser) parseMatchStatement() *ast.MatchStatement {
	match := &ast.MatchStatement{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Host) {
		match.Condition = token.Host
	}

	if !p.expectPeek(token.STRING) {
		return nil
	}

	match.Value = p.curToken.Literal

	return match
}
