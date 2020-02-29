package parser

import (
	"github.com/calvernaz/scp/ast"
	"github.com/calvernaz/scp/lexer"
	"github.com/calvernaz/scp/token"
)

type Parser struct {
	l *lexer.Lexer

	curToken  token.Token
	peekToken token.Token
	errors    []string
}

func New(l *lexer.Lexer) *Parser {
	p := &Parser{l: l}

	// Read two tokens, so curToken and peekToken are both set
	p.nextToken()
	p.nextToken()

	return p
}

// ParseConfig entrypoint to parse the SSH configuration
func (p *Parser) ParseConfig() *ast.SshConfig {
	config := &ast.SshConfig{}
	config.Statements = []ast.Statement{}

	for p.curToken.Type != token.EOF {
		stmt := p.parseStatement()
		if stmt != nil {
			config.Statements = append(config.Statements, stmt)
		}
		//p.nextToken()
	}
	return config
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

func (p *Parser) parseStatement() ast.Statement {
	switch p.curToken.Type {
	case token.HOST:
		return p.parseHostStatement()
	case token.HOSTNAME:
		return p.parseHostnameStatement()
	case token.IDENTITY_FILE:
		return p.parseIdentityFileStatement()
	case token.USER:
		return p.parseUserStatement()
	case token.PORT:
		return p.parsePortStatement()
	case token.USE_KEY_CHAIN:
		return p.parseUseKeyStatement()
	case token.ADD_KEYS_TO_AGENT:
		return p.parseAddKeysToAgentStatement()
	case token.LOCAL_FORWARD:
		return p.parseLocalForwardStatement()
	//case token.MATCH:
	//	return p.parseMatchStatement()
	default:
		return nil
	}
}

func (p *Parser) parseHostStatement() *ast.HostStatement {
	stmt := &ast.HostStatement{Token: p.curToken}

	p.nextToken()

	// Host <value>
	if p.curTokenIs(token.STAR) || p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	// we proceed with the host block parsing
	// if the next token is not "Host"
	if !p.expectPeek(token.HOST) {
		stmt.Statement = p.parseBlockStatement()
	}

	return stmt
}

func (p *Parser) parseBlockStatement() *ast.BlockStatement {
	block := &ast.BlockStatement{}
	block.Statements = []ast.Statement{}

	p.nextToken()

	//for !p.curTokenIs(token.MATCH) && !p.curTokenIs(token.HOST) && !p.curTokenIs(token.EOF) {
	for !p.expectPeek(token.HOST) && !p.curTokenIs(token.EOF) {
		stmt := p.parseStatement()
		if stmt != nil {
			block.Statements = append(block.Statements, stmt)
		} else {
			p.nextToken()
		}
	}
	return block
}

func (p *Parser) Errors() []string {
	return p.errors
}

//func (p *Parser) parseMatchStatement() *ast.MatchStatement {
//	match := &ast.MatchStatement{Token: p.curToken}
//
//	p.nextToken()
//
//	if p.curTokenIs(token.Host) {
//		match.Condition = token.Host
//	}
//
//	if !p.expectPeek(token.STRING) {
//		return nil
//	}
//
//	match.Value = p.curToken.Literal
//
//	return match
//}
