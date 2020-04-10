package parser

import (
	"fmt"
	"log"
	"strings"

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
		} else if len(p.errors) > 0 {
			log.Println("parsing errors were found")
			return config
		}
		p.nextToken()
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
	case token.COMPRESSION:
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
		return p.parseHostKeyAlgorithms()
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
	case token.PKCS11_PROVIDER:
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
		return p.parseXAuthLocation()
	//case token.MATCH:
	//	return p.parseMatchStatement()
	default:
		return nil
	}
}

func (p *Parser) parseHostStatement() *ast.HostStatement {
	stmt := &ast.HostStatement{Token: p.curToken}

	// Host <value>
	var s []string
	if  !p.peekTokenIs(token.IDENT) {
		p.errors = append(p.errors, fmt.Sprint("failed to parse host statement"))
		return nil
	}

	for p.expectPeek(token.IDENT) {
		s = append(s, p.curToken.Literal)
	}
	stmt.Value = strings.Join(s, " ")

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

	for !p.peekTokenIs(token.HOST) && !p.curTokenIs(token.EOF) {
		stmt := p.parseStatement()
		if stmt != nil {
			block.Statements = append(block.Statements, stmt)
		} else {
			p.nextToken()
		}
	}
	return block
}


// Specifies the real host name to log into.
func (p *Parser) parseHostname() ast.Statement {
	stmt := &ast.HostName{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseIdentityFile() ast.Statement {
	stmt := &ast.IdentityFile{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseUser() ast.Statement {
	stmt := &ast.User{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parsePort() ast.Statement {
	stmt := &ast.Port{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseUseKeyChain() ast.Statement {
	stmt := &ast.UseKeyChain{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseAddKeysToAgent() ast.Statement {
	stmt := &ast.AddKeysToAgent{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseLocalForward() ast.Statement {
	stmt := &ast.LocalForward{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = stmt.Value + " " + p.curToken.Literal
	}
	return stmt
}

func (p *Parser) parseControlMaster() ast.Statement {
	stmt := &ast.ControlMaster{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseControlPersist() ast.Statement {
	stmt := &ast.ControlPersist{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseServerAlive() ast.Statement {
	stmt := &ast.ServerAliveOption{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseCompression() ast.Statement {
	stmt := &ast.CompressionStatement{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseCompressionLevel() ast.Statement {
	stmt := &ast.CompressionLevelStatement{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseUserKnownHostsFile() ast.Statement {
	stmt := &ast.UserKnownHostsFile{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.COMMA) {
		p.nextToken()
		stmt.Value = stmt.Value + ", " + p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseStrictHostKeyChecking() ast.Statement {
	stmt := &ast.StrictHostKeyChecking{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.COMMA) {
		p.nextToken()
		stmt.Value = stmt.Value + ", " + p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseProxyCommand() ast.Statement {
	stmt := &ast.ProxyCommandStatement{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.IDENT) {
		stmt.Value = stmt.Value + " " + p.curToken.Literal
	}
	return stmt
}

func (p *Parser) parseForwardAgent() ast.Statement {
	stmt := &ast.ForwardAgent{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseLogLevel() ast.Statement {
	stmt := &ast.LogLevelStatement{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseCanonicalizeFallback() ast.Statement {
	stmt := &ast.CanonicalizeFallbackLocal{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseCanonicalizeHostname() ast.Statement {
	stmt := &ast.CanonicalizeHostname{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseCanonicalizeMaxDots() ast.Statement {
	stmt := &ast.CanonicalizeMaxDots{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseCanonicalizePermittedCNames() ast.Statement {
	stmt := &ast.CanonicalizePermittedCNames{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.IDENT) {
		stmt.Value = stmt.Value + " " + p.curToken.Literal
	}
	return stmt
}

func (p *Parser) parseCaSignatureAlgorithms() ast.Statement {
	stmt := &ast.CASignatureAlgorithms{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.COMMA) {
		p.nextToken()
		stmt.Value = stmt.Value + ", " + p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseCertificateFile() ast.Statement {
	stmt := &ast.CertificateFile{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseChallengeAuthentication() ast.Statement {
	stmt := &ast.ChallengeAuthentication{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseCheckHostIP() ast.Statement {
	stmt := &ast.CheckHostIP{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseCiphers() ast.Statement {
	stmt := &ast.Ciphers{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.COMMA) {
		p.nextToken()
		stmt.Value = stmt.Value + ", " + p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseClearAllForwarding() ast.Statement {
	stmt := &ast.ClearAllForwardings{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseConnectionAttempts() ast.Statement {
	stmt := &ast.ConnectionAttempts{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseConnectionTimeout() ast.Statement {
	stmt := &ast.ConnectionTimeout{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseDynamicForward() ast.Statement {
	stmt := &ast.DynamicForward{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseEscapeChar() ast.Statement {
	stmt := &ast.EscapeChar{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseExitOnForwardFailure() ast.Statement {
	stmt := &ast.ExitOnForwardFailure{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseFingerprintHash() ast.Statement {
	stmt := &ast.FingerprintHash{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseForwardX11() ast.Statement {
	stmt := &ast.ForwardX11{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseForwardX11Timeout() ast.Statement {
	stmt := &ast.ForwardX11Timeout{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseForwardX11Trusted() ast.Statement {
	stmt := &ast.ForwardX11Trusted{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseGatewayPorts() ast.Statement {
	stmt := &ast.GatewayPorts{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseGlobalKnownHostsFile() ast.Statement {
	stmt := &ast.GlobalKnownHostsFile{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.COMMA) {
		p.nextToken()
		stmt.Value = stmt.Value + ", " + p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseGSSApiAuthentication() ast.Statement {
	stmt := &ast.GSSApiAuthentication{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseGSSApiDelegateCredentials() ast.Statement {
	stmt := &ast.GSSApiDelegateCredentials{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseHashKnownHosts() ast.Statement {
	stmt := &ast.HashKnownHosts{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseHostBasedAuthentication() ast.Statement {
	stmt := &ast.HostBasedAuthentication{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseHostBasedKeyTypes() ast.Statement {
	stmt := &ast.HostBasedKeyTypes{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.COMMA) {
		p.nextToken()
		stmt.Value = stmt.Value + ", " + p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseHostKeyAlgorithms() ast.Statement {
	stmt := &ast.HostKeyAlgorithms{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.COMMA) {
		p.nextToken()
		stmt.Value = stmt.Value + ", " + p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseHostKeyAlias() ast.Statement {
	stmt := &ast.HostKeyAlias{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseIdentitiesOnly() ast.Statement {
	stmt := &ast.IdentitiesOnly{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseIdentityAgent() ast.Statement {
	stmt := &ast.IdentityAgent{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseIPQoS() ast.Statement {
	stmt := &ast.IPQoS{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseKbdInteractiveAuthentication() ast.Statement {
	stmt := &ast.KbdInteractiveAuthentication{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseKbdInteractiveDevices() ast.Statement {
	stmt := &ast.KbdInteractiveDevices{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.COMMA) {
		p.nextToken()
		stmt.Value = stmt.Value + ", " + p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseLocalCommand() ast.Statement {
	stmt := &ast.LocalCommand{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.IDENT) {
		stmt.Value = stmt.Value + " " + p.curToken.Literal
	}
	return stmt
}


func (p *Parser) parseMacs() ast.Statement {
	stmt := &ast.Macs{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.COMMA) {
		p.nextToken()
		stmt.Value = stmt.Value + ", " + p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseNoHostAuthentication() ast.Statement {
	stmt := &ast.NoHostAuthentication{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseNumberOfPasswordPrompts() ast.Statement {
	stmt := &ast.NumberOfPasswordPrompts{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parsePasswordAuthentication() ast.Statement {
	stmt := &ast.PasswordAuthentication{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parsePermitLocalCommand() ast.Statement {
	stmt := &ast.PermitLocalCommand{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parsePCKS11Provider() ast.Statement {
	stmt := &ast.PCKS11Provider{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parsePreferredAuthentications() ast.Statement {
	stmt := &ast.PreferredAuthentications{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.COMMA) {
		p.nextToken()
		stmt.Value = stmt.Value + ", " + p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseProxyJump() ast.Statement {
	stmt := &ast.ProxyJump{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseProxyUseFD() ast.Statement {
	stmt := &ast.ProxyUserFDPass{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parsePubkeyAcceptedKeyTypes() ast.Statement {
	stmt := &ast.PubkeyAcceptedKeyTypes{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parsePubkeyAuthentication() ast.Statement {
	stmt := &ast.PubkeyAuthentication{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseRekeyLimit() ast.Statement {
	stmt := &ast.RekeyLimit{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseRemoteCommand() ast.Statement {
	stmt := &ast.RemoteCommand{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.IDENT) {
		stmt.Value = stmt.Value + " " + p.curToken.Literal
	}
	return stmt
}


func (p *Parser) parseRemoteForward() ast.Statement {
	stmt := &ast.RemoteForward{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.IDENT) {
		stmt.Value = stmt.Value + " " + p.curToken.Literal
	}
	return stmt
}


func (p *Parser) parseRequestTTY() ast.Statement {
	stmt := &ast.RequestTTY{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseSendEnv() ast.Statement {
	stmt := &ast.SendEnv{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.IDENT) {
		stmt.Value = stmt.Value + " " + p.curToken.Literal
	}
	return stmt
}


func (p *Parser) parseSetEnv() ast.Statement {
	stmt := &ast.SetEnv{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseStreamLocalBindMask() ast.Statement {
	stmt := &ast.StreamLocalBindMask{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseStreamLocalBindUnlink() ast.Statement {
	stmt := &ast.StreamLocalBindUnlink{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseTcpKeepAlive() ast.Statement {
	stmt := &ast.TcpKeepAlive{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseTunnel() ast.Statement {
	stmt := &ast.Tunnel{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseTunnelDevice() ast.Statement {
	stmt := &ast.TunnelDevice{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseUpdateHostKeys() ast.Statement {
	stmt := &ast.UpdateHostKeys{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseVerifyHostKeyDNS() ast.Statement {
	stmt := &ast.VerifyHostKeyDNS{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseVisualHostKey() ast.Statement {
	stmt := &ast.VisualHostKey{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}


func (p *Parser) parseXAuthLocation() ast.Statement {
	stmt := &ast.XAuthLocation{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseControlPath() ast.Statement {
	stmt := &ast.ControlPath{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
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
