package parser

import (
	"fmt"
	"log"
	"strings"

	"github.com/calvernaz/scp/ast"
	"github.com/calvernaz/scp/lexer"
	"github.com/calvernaz/scp/token"
)

// Parser ...
type Parser struct {
	l *lexer.Lexer

	curToken  token.Token
	peekToken token.Token
	errors    []string
}

// New ...
func New(l *lexer.Lexer) *Parser {
	p := &Parser{l: l}

	// Read two tokens, so curToken and peekToken are both set
	p.nextToken()
	p.nextToken()

	return p
}

// ParseConfig entrypoint to parse the SSH configuration
func (p *Parser) ParseConfig() *ast.SSHConfig {
	config := &ast.SSHConfig{}
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

func (p *Parser) curTokenIs(t token.Type) bool {
	return p.curToken.Type == t
}

func (p *Parser) peekTokenIs(t token.Type) bool {
	return p.peekToken.Type == t
}

func (p *Parser) expectPeek(t token.Type) bool {
	if p.peekTokenIs(t) {
		p.nextToken()
		return true
	}
	return false
}

func (p *Parser) parseStatement() ast.Statement {
	switch p.curToken.Type {
	case token.Host:
		return p.parseHostStatement()
	case token.Hostname:
		return p.parseHostname()
	case token.IdentityFile:
		return p.parseIdentityFile()
	case token.User:
		return p.parseUser()
	case token.Port:
		return p.parsePort()
	case token.UseKeyChain:
		return p.parseUseKeyChain()
	case token.AddKeysToAgent:
		return p.parseAddKeysToAgent()
	case token.LocalForward:
		return p.parseLocalForward()
	case token.ControlMaster:
		return p.parseControlMaster()
	case token.ControlPath:
		return p.parseControlPath()
	case token.ControlPersist:
		return p.parseControlPersist()
	case token.ServerAliveInterval, token.ServerAliveCountMax:
		return p.parseServerAlive()
	case token.Compression:
		return p.parseCompression()
	case token.UserKnownHostsFile:
		return p.parseUserKnownHostsFile()
	case token.StrictHostKeyChecking:
		return p.parseStrictHostKeyChecking()
	case token.ProxyCommand:
		return p.parseProxyCommand()
	case token.ForwardAgent:
		return p.parseForwardAgent()
	case token.LogLevel:
		return p.parseLogLevel()
	case token.CanonicalizeFallbackLocal:
		return p.parseCanonicalizeFallback()
	case token.CanonicalizeHostname:
		return p.parseCanonicalizeHostname()
	case token.CanonicalizeMaxDots:
		return p.parseCanonicalizeMaxDots()
	case token.CanonicalizePermittedCnames:
		return p.parseCanonicalizePermittedCNames()
	case token.CaSignatureAlgorithms:
		return p.parseCaSignatureAlgorithms()
	case token.CertificateFile:
		return p.parseCertificateFile()
	case token.ChallengeResponseAuthentication:
		return p.parseChallengeAuthentication()
	case token.CheckHostIP:
		return p.parseCheckHostIP()
	case token.Ciphers:
		return p.parseCiphers()
	case token.ClearAllForwardings:
		return p.parseClearAllForwarding()
	case token.ConnectionAttempts:
		return p.parseConnectionAttempts()
	case token.ConnectionTimeout:
		return p.parseConnectionTimeout()
	case token.DynamicForward:
		return p.parseDynamicForward()
	case token.EscapeChar:
		return p.parseEscapeChar()
	case token.ExitOnForwardFailure:
		return p.parseExitOnForwardFailure()
	case token.FingerprintHash:
		return p.parseFingerprintHash()
	case token.ForwardX11:
		return p.parseForwardX11()
	case token.ForwardX11Timeout:
		return p.parseForwardX11Timeout()
	case token.ForwardX11Trusted:
		return p.parseForwardX11Trusted()
	case token.GatewayPorts:
		return p.parseGatewayPorts()
	case token.GlobalKnownHostsFile:
		return p.parseGlobalKnownHostsFile()
	case token.GSSAPIAuthentication:
		return p.parseGSSApiAuthentication()
	case token.GSSAPIDelegateCredentials:
		return p.parseGSSApiDelegateCredentials()
	case token.HashKnownHosts:
		return p.parseHashKnownHosts()
	case token.HostbasedAuthentication:
		return p.parseHostBasedAuthentication()
	case token.HostbasedKeyTypes:
		return p.parseHostBasedKeyTypes()
	case token.HostbasedKeyAlgorithms:
		return p.parseHostKeyAlgorithms()
	case token.HostKeyAlias:
		return p.parseHostKeyAlias()
	case token.IdentitiesOnly:
		return p.parseIdentitiesOnly()
	case token.IdentityAgent:
		return p.parseIdentityAgent()
	case token.IPQoS:
		return p.parseIPQoS()
	case token.KbdInteractiveAuthentication:
		return p.parseKbdInteractiveAuthentication()
	case token.KbdInteractiveDevices:
		return p.parseKbdInteractiveDevices()
	case token.LocalCommand:
		return p.parseLocalCommand()
	case token.Macs:
		return p.parseMacs()
	case token.NoHostAuthenticationForLocalhost:
		return p.parseNoHostAuthentication()
	case token.NumberOfPasswordPrompts:
		return p.parseNumberOfPasswordPrompts()
	case token.PasswordAuthentication:
		return p.parsePasswordAuthentication()
	case token.PermitLocalCommand:
		return p.parsePermitLocalCommand()
	case token.Pkcs11Provider:
		return p.parsePCKS11Provider()
	case token.PreferredAuthentications:
		return p.parsePreferredAuthentications()
	case token.ProxyJump:
		return p.parseProxyJump()
	case token.ProxyUseFdpass:
		return p.parseProxyUseFD()
	case token.PubkeyAcceptedKeyTypes:
		return p.parsePubkeyAcceptedKeyTypes()
	case token.PubkeyAuthentication:
		return p.parsePubkeyAuthentication()
	case token.RekeyLimit:
		return p.parseRekeyLimit()
	case token.RemoteCommand:
		return p.parseRemoteCommand()
	case token.RemoteForward:
		return p.parseRemoteForward()
	case token.RequestTty:
		return p.parseRequestTTY()
	case token.SendEnv:
		return p.parseSendEnv()
	case token.SetEnv:
		return p.parseSetEnv()
	case token.StreamLocalBindMask:
		return p.parseStreamLocalBindMask()
	case token.StreamLocalBindUnlink:
		return p.parseStreamLocalBindUnlink()
	case token.TCPKeepAlive:
		return p.parseTCPKeepAlive()
	case token.Tunnel:
		return p.parseTunnel()
	case token.TunnelDevice:
		return p.parseTunnelDevice()
	case token.UpdateHostKeys:
		return p.parseUpdateHostKeys()
	case token.VerifyHostKeyDNS:
		return p.parseVerifyHostKeyDNS()
	case token.VisualHostKey:
		return p.parseVisualHostKey()
	case token.XauthLocation:
		return p.parseXAuthLocation()
	case token.Include:
		return p.parseInclude()
	//case token.Match:
	//	return p.parseMatchStatement()
	default:
		return nil
	}
}

func (p *Parser) parseHostStatement() *ast.HostStatement {
	stmt := &ast.HostStatement{Token: p.curToken}

	// Host <value>
	var s []string
	if !p.peekTokenIs(token.Ident) {
		p.errors = append(p.errors, fmt.Sprint("failed to parse host statement"))
		return nil
	}

	for p.expectPeek(token.Ident) {
		s = append(s, p.curToken.Literal)
	}
	stmt.Value = strings.Join(s, " ")

	// we proceed with the host block parsing
	// if the next token is not "Host"
	if !p.expectPeek(token.Host) {
		stmt.Statement = p.parseBlockStatement()
	}

	return stmt
}

func (p *Parser) parseBlockStatement() *ast.BlockStatement {
	block := &ast.BlockStatement{}
	block.Statements = []ast.Statement{}

	p.nextToken()

	for !p.peekTokenIs(token.Host) && !p.curTokenIs(token.EOF) {
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

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseIdentityFile() ast.Statement {
	stmt := &ast.IdentityFile{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseUser() ast.Statement {
	stmt := &ast.User{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parsePort() ast.Statement {
	stmt := &ast.Port{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseUseKeyChain() ast.Statement {
	stmt := &ast.UseKeyChain{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseAddKeysToAgent() ast.Statement {
	stmt := &ast.AddKeysToAgent{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseLocalForward() ast.Statement {
	stmt := &ast.LocalForward{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = stmt.Value + " " + p.curToken.Literal
	}
	return stmt
}

func (p *Parser) parseControlMaster() ast.Statement {
	stmt := &ast.ControlMaster{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseControlPersist() ast.Statement {
	stmt := &ast.ControlPersist{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseServerAlive() ast.Statement {
	stmt := &ast.ServerAliveOption{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseCompression() ast.Statement {
	stmt := &ast.Compression{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseCompressionLevel() ast.Statement {
	stmt := &ast.CompressionLevelStatement{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseUserKnownHostsFile() ast.Statement {
	stmt := &ast.UserKnownHostsFile{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.Comma) {
		p.nextToken()
		stmt.Value = stmt.Value + ", " + p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseStrictHostKeyChecking() ast.Statement {
	stmt := &ast.StrictHostKeyChecking{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.Comma) {
		p.nextToken()
		stmt.Value = stmt.Value + ", " + p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseProxyCommand() ast.Statement {
	stmt := &ast.ProxyCommand{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.Ident) {
		stmt.Value = stmt.Value + " " + p.curToken.Literal
	}
	return stmt
}

func (p *Parser) parseForwardAgent() ast.Statement {
	stmt := &ast.ForwardAgent{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseLogLevel() ast.Statement {
	stmt := &ast.LogLevelStatement{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseCanonicalizeFallback() ast.Statement {
	stmt := &ast.CanonicalizeFallbackLocal{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseCanonicalizeHostname() ast.Statement {
	stmt := &ast.CanonicalizeHostname{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseCanonicalizeMaxDots() ast.Statement {
	stmt := &ast.CanonicalizeMaxDots{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseCanonicalizePermittedCNames() ast.Statement {
	stmt := &ast.CanonicalizePermittedCNames{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.Ident) {
		stmt.Value = stmt.Value + " " + p.curToken.Literal
	}
	return stmt
}

func (p *Parser) parseCaSignatureAlgorithms() ast.Statement {
	stmt := &ast.CASignatureAlgorithms{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.Comma) {
		p.nextToken()
		stmt.Value = stmt.Value + ", " + p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseCertificateFile() ast.Statement {
	stmt := &ast.CertificateFile{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseChallengeAuthentication() ast.Statement {
	stmt := &ast.ChallengeAuthentication{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseCheckHostIP() ast.Statement {
	stmt := &ast.CheckHostIP{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseCiphers() ast.Statement {
	stmt := &ast.Ciphers{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.Comma) {
		p.nextToken()
		stmt.Value = stmt.Value + ", " + p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseClearAllForwarding() ast.Statement {
	stmt := &ast.ClearAllForwardings{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseConnectionAttempts() ast.Statement {
	stmt := &ast.ConnectionAttempts{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseConnectionTimeout() ast.Statement {
	stmt := &ast.ConnectionTimeout{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseDynamicForward() ast.Statement {
	stmt := &ast.DynamicForward{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseEscapeChar() ast.Statement {
	stmt := &ast.EscapeChar{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseExitOnForwardFailure() ast.Statement {
	stmt := &ast.ExitOnForwardFailure{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseFingerprintHash() ast.Statement {
	stmt := &ast.FingerprintHash{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseForwardX11() ast.Statement {
	stmt := &ast.ForwardX11{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseForwardX11Timeout() ast.Statement {
	stmt := &ast.ForwardX11Timeout{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseForwardX11Trusted() ast.Statement {
	stmt := &ast.ForwardX11Trusted{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseGatewayPorts() ast.Statement {
	stmt := &ast.GatewayPorts{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseGlobalKnownHostsFile() ast.Statement {
	stmt := &ast.GlobalKnownHostsFile{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.Comma) {
		p.nextToken()
		stmt.Value = stmt.Value + ", " + p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseGSSApiAuthentication() ast.Statement {
	stmt := &ast.GSSApiAuthentication{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseGSSApiDelegateCredentials() ast.Statement {
	stmt := &ast.GSSApiDelegateCredentials{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseHashKnownHosts() ast.Statement {
	stmt := &ast.HashKnownHosts{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseHostBasedAuthentication() ast.Statement {
	stmt := &ast.HostBasedAuthentication{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseHostBasedKeyTypes() ast.Statement {
	stmt := &ast.HostBasedKeyTypes{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.Comma) {
		p.nextToken()
		stmt.Value = stmt.Value + ", " + p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseHostKeyAlgorithms() ast.Statement {
	stmt := &ast.HostKeyAlgorithms{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.Comma) {
		p.nextToken()
		stmt.Value = stmt.Value + ", " + p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseHostKeyAlias() ast.Statement {
	stmt := &ast.HostKeyAlias{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseIdentitiesOnly() ast.Statement {
	stmt := &ast.IdentitiesOnly{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseIdentityAgent() ast.Statement {
	stmt := &ast.IdentityAgent{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseIPQoS() ast.Statement {
	stmt := &ast.IPQoS{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseKbdInteractiveAuthentication() ast.Statement {
	stmt := &ast.KbdInteractiveAuthentication{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseKbdInteractiveDevices() ast.Statement {
	stmt := &ast.KbdInteractiveDevices{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.Comma) {
		p.nextToken()
		stmt.Value = stmt.Value + ", " + p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseLocalCommand() ast.Statement {
	stmt := &ast.LocalCommand{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.Ident) {
		stmt.Value = stmt.Value + " " + p.curToken.Literal
	}
	return stmt
}

func (p *Parser) parseMacs() ast.Statement {
	stmt := &ast.Macs{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.Comma) {
		p.nextToken()
		stmt.Value = stmt.Value + ", " + p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseNoHostAuthentication() ast.Statement {
	stmt := &ast.NoHostAuthentication{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseNumberOfPasswordPrompts() ast.Statement {
	stmt := &ast.NumberOfPasswordPrompts{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parsePasswordAuthentication() ast.Statement {
	stmt := &ast.PasswordAuthentication{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parsePermitLocalCommand() ast.Statement {
	stmt := &ast.PermitLocalCommand{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parsePCKS11Provider() ast.Statement {
	stmt := &ast.PCKS11Provider{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parsePreferredAuthentications() ast.Statement {
	stmt := &ast.PreferredAuthentications{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.Comma) {
		p.nextToken()
		stmt.Value = stmt.Value + ", " + p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseProxyJump() ast.Statement {
	stmt := &ast.ProxyJump{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseProxyUseFD() ast.Statement {
	stmt := &ast.ProxyUserFDPass{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parsePubkeyAcceptedKeyTypes() ast.Statement {
	stmt := &ast.PubkeyAcceptedKeyTypes{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parsePubkeyAuthentication() ast.Statement {
	stmt := &ast.PubkeyAuthentication{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseRekeyLimit() ast.Statement {
	stmt := &ast.RekeyLimit{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseRemoteCommand() ast.Statement {
	stmt := &ast.RemoteCommand{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.Ident) {
		stmt.Value = stmt.Value + " " + p.curToken.Literal
	}
	return stmt
}

func (p *Parser) parseRemoteForward() ast.Statement {
	stmt := &ast.RemoteForward{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.Ident) {
		stmt.Value = stmt.Value + " " + p.curToken.Literal
	}
	return stmt
}

func (p *Parser) parseRequestTTY() ast.Statement {
	stmt := &ast.RequestTTY{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseSendEnv() ast.Statement {
	stmt := &ast.SendEnv{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	for p.expectPeek(token.Ident) {
		stmt.Value = stmt.Value + " " + p.curToken.Literal
	}
	return stmt
}

func (p *Parser) parseSetEnv() ast.Statement {
	stmt := &ast.SetEnv{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseStreamLocalBindMask() ast.Statement {
	stmt := &ast.StreamLocalBindMask{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseStreamLocalBindUnlink() ast.Statement {
	stmt := &ast.StreamLocalBindUnlink{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseTCPKeepAlive() ast.Statement {
	stmt := &ast.TCPKeepAlive{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseTunnel() ast.Statement {
	stmt := &ast.Tunnel{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseTunnelDevice() ast.Statement {
	stmt := &ast.TunnelDevice{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseUpdateHostKeys() ast.Statement {
	stmt := &ast.UpdateHostKeys{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseVerifyHostKeyDNS() ast.Statement {
	stmt := &ast.VerifyHostKeyDNS{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseVisualHostKey() ast.Statement {
	stmt := &ast.VisualHostKey{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseXAuthLocation() ast.Statement {
	stmt := &ast.XAuthLocation{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

func (p *Parser) parseControlPath() ast.Statement {
	stmt := &ast.ControlPath{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.Ident) {
		stmt.Value = p.curToken.Literal
	}

	return stmt
}

// Errors ....
func (p *Parser) Errors() []string {
	return p.errors
}

func (p *Parser) parseInclude() ast.Statement {
	stmt := &ast.Include{ Token: p.curToken }
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
