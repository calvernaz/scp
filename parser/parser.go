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
		return p.parseHostname()
	case token.IDENTITY_FILE:
		return p.parseIdentityFile()
	case token.USER:
		return p.parseUser()
	case token.PORT:
		return p.parsePort()
	case token.USE_KEY_CHAIN:
		return p.parseUseKeyChain()
	case token.ADD_KEYS_TO_AGENT:
		return p.parseAddKeysToAgent()
	case token.LOCAL_FORWARD:
		return p.parseLocalForward()
	case token.CONTROL_MASTER:
		return p.parseControlMaster()
	case token.CONTROL_PATH:
		return p.parseControlPath()
	case token.CONTROL_PERSIST:
		return p.parseControlPersist()
	case token.SERVER_ALIVE_INTERVAL, token.SERVER_ALIVE_COUNT_MAX:
		return p.parseServerAlive()
	case token.COMPRESION:
		return p.parseCompression()
	case token.USER_KNOWN_HOSTS_FILE:
		return p.parseUserKnownHostsFile()
	case token.STRICT_HOST_KEY_CHECKING:
		return p.parseStrictHostKeyChecking()
	case token.PROXY_COMMAND:
		return p.parseProxyCommand()
	case token.FORWARD_AGENT:
		return p.parseForwardAgent()
	case token.LOG_LEVEL:
		return p.parseLogLevel()
	case token.CANONICALIZE_FALLBACK_LOCAL:
		return p.parseCanonicalizeFallback()
	case token.CANONICALIZE_HOSTNAME:
		return p.parseCanonicalizeHostname()
	case token.CANONICALIZE_MAX_DOTS:
		return p.parseCanonicalizeMaxDots()
	case token.CANONICALIZE_PERMITTED_CNAMES:
		return p.parseCanonicalizePermittedCNames()
	case token.CA_SIGNATURE_ALGORITHMS:
		return p.parseCaSignatureAlgorithms()
	case token.CERTIFICATE_FILE:
		return p.parseCertificateFile()
	case token.CHALLENGE_RESPONSE_AUTHENTICATION:
		return p.parseChallengeAuthentication()
	case token.CHECK_HOST_IP:
		return p.parseCheckHostIP()
	case token.CIPHERS:
		return p.parseCiphers()
	case token.CLEAR_ALL_FORWARDINGS:
		return p.parseClearAllForwarding()
	case token.CONNECTION_ATTEMPTS:
		return p.parseConnectionAttempts()
	case token.CONNECTION_TIMEOUT:
		return p.parseConnectionTimeout()
	case token.DYNAMIC_FORWARD:
		return p.parseDynamicForward()
	case token.ESCAPE_CHAR:
		return p.parseEscapeChar()
	case token.EXIT_ON_FORWARD_FAILURE:
		return p.parseExitOnForwardFailure()
	case token.FINGERPRINT_HASH:
		return p.parseFingerprintHash()
	case token.FORWARD_X11:
		return p.parseForwardX11()
	case token.FORWARD_X11_TIMEOUT:
		return p.parseForwardX11Timeout()
	case token.FORWARD_X11_TRUSTED:
		return p.parseForwardX11Trusted()
	case token.GATEWAY_PORTS:
		return p.parseGatewayPorts()
	case token.GLOBAL_KNOWN_HOSTS_FILE:
		return p.parseGlobalKnownHostsFile()
	case token.GSSAPI_AUTHENTICATION:
		return p.parseGSSApiAuthentication()
	case token.GSSAPI_DELEGATE_CREDENTIALS:
		return p.parseGSSApiDelegateCredentials()
	case token.HASH_KNOWN_HOSTS:
		return p.parseHashKnownHosts()
	case token.HOSTBASED_AUTHENTICATION:
		return p.parseHostBasedAuthentication()
	case token.HOSTBASED_KEY_TYPES:
		return p.parseHostBasedKeyTypes()
	case token.HOSTBASED_KEY_ALGORITHMS:
		return p.parseHostBasedKeyAlgorithms()
	case token.HOST_KEY_ALIAS:
		return p.parseHostKeyAlias()
	case token.IDENTITIES_ONLY:
		return p.parseIdentitiesOnly()
	case token.IDENTITY_AGENT:
		return p.parseIdentityAgent()
	case token.IP_QOS:
		return p.parseIPQoS()
	case token.KBD_INTERACTIVE_AUTHENTICATION:
		return p.parseKbdInteractiveAuthentication()
	case token.KBD_INTERACTIVE_DEVICES:
		return p.parseKbdInteractiveDevices()
	case token.KEX_ALGORITHMS:
		return p.parseKeyAlgorithms()
	case token.LOCAL_COMMAND:
		return p.parseLocalCommand()
	case token.MACS:
		return p.parseMacs()
	case token.NO_HOST_AUTHENTICATION_FOR_LOCALHOST:
		return p.parseNoHostAuthentication()
	case token.NUMBER_OF_PASSWORD_PROMPTS:
		return p.parseNumberOfPasswordPrompts()
	case token.PASSWORD_AUTHENTICATION:
		return p.parsePasswordAuthentication()
	case token.PERMIT_LOCAL_COMMAND:
		return p.parsePermitLocalCommand()
	case token.PCKS11_PROVIDER:
		return p.parsePCKS11Provider()
	case token.PREFERRED_AUTHENTICATIONS:
		return p.parsePreferredAuthentications()
	case token.PROXY_JUMP:
		return p.parseProxyJump()
	case token.PROXY_USE_FDPASS:
		return p.parseProxyUseFD()
	case token.PUBKEY_ACCEPTED_KEY_TYPES:
		return p.parsePubkeyAcceptedKeyTypes()
	case token.PUBKEY_AUTHENTICATION:
		return p.parsePubkeyAuthentication()
	case token.REKEY_LIMIT:
		return p.parseRekeyLimit()
	case token.REMOTE_COMMAND:
		return p.parseRemoteCommand()
	case token.REMOTE_FORWARD:
		return p.parseRemoteForward()
	case token.REQUEST_TTY:
		return p.parseRequestTTY()
	case token.SEND_ENV:
		return p.parseSendEnv()
	case token.SET_ENV:
		return p.parseSetEnv()
	case token.STREAM_LOCAL_BIND_MASK:
		return p.parseStreamLocalBindMask()
	case token.STREAM_LOCAL_BIND_UNLINK:
		return p.parseStreamLocalBindUnlink()
	case token.TCP_KEEP_ALIVE:
		return p.parseTcpKeepAlive()
	case token.TUNNEL:
		return p.parseTunnel()
	case token.TUNNEL_DEVICE:
		return p.parseTunnelDevice()
	case token.UPDATE_HOST_KEYS:
		return p.parseUpdateHostKeys()
	case token.VERIFY_HOST_KEY_DNS:
		return p.parseVerifyHostKeyDNS()
	case token.VISUAL_HOST_KEY:
		return p.parseVisualHostKey()
	case token.XAUTH_LOCATION:
		return p.parseHostStatement()
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

func (p *Parser) parseControlPath() ast.Statement {
	stmt := &ast.IdentityFile{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
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
