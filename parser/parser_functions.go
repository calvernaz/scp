package parser

import (
	"github.com/calvernaz/scp/ast"
	"github.com/calvernaz/scp/token"
)

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

	p.nextToken()

	return stmt
}

func (p *Parser) parseControlPersist() ast.Statement {
	stmt := &ast.ControlPersist{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	p.nextToken()

	return stmt
}

func (p *Parser) parseServerAlive() ast.Statement {
	stmt := &ast.ServerAliveOption{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
	}

	p.nextToken()

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


func (p *Parser) parseKeyAlgorithms() ast.Statement {
	stmt := &ast.KeyAlgorithms{Token: p.curToken}

	p.nextToken()

	if p.curTokenIs(token.IDENT) {
		stmt.Value = p.curToken.Literal
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
