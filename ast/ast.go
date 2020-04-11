package ast

import (
	"bytes"

	"github.com/calvernaz/scp/token"
)

var (
	_ Statement = (*HostStatement)(nil)
	_ Statement = (*BlockStatement)(nil)
	_ Statement = (*HostName)(nil)
	_ Statement = (*IdentityFile)(nil)
	_ Statement = (*User)(nil)
	_ Statement = (*Port)(nil)
	_ Statement = (*UseKeyChain)(nil)
	_ Statement = (*AddKeysToAgent)(nil)
	_ Statement = (*LocalForward)(nil)
	_ Statement = (*ControlMaster)(nil)
	_ Statement = (*ControlPersist)(nil)
	_ Statement = (*ServerAliveOption)(nil)
	_ Statement = (*Compression)(nil)
	_ Statement = (*CompressionLevelStatement)(nil)
	_ Statement = (*UserKnownHostsFile)(nil)
	_ Statement = (*StrictHostKeyChecking)(nil)
	_ Statement = (*ProxyCommand)(nil)
	_ Statement = (*ForwardAgent)(nil)
	_ Statement = (*LogLevelStatement)(nil)
	_ Statement = (*CanonicalizeFallbackLocal)(nil)
	_ Statement = (*CanonicalizeHostname)(nil)
	_ Statement = (*CanonicalizeMaxDots)(nil)
	_ Statement = (*CanonicalizePermittedCNames)(nil)
	_ Statement = (*CASignatureAlgorithms)(nil)
	_ Statement = (*CertificateFile)(nil)
	_ Statement = (*ChallengeAuthentication)(nil)
	_ Statement = (*CheckHostIP)(nil)
	_ Statement = (*Ciphers)(nil)
	_ Statement = (*ClearAllForwardings)(nil)
	_ Statement = (*ConnectionAttempts)(nil)
	_ Statement = (*ConnectionTimeout)(nil)
	_ Statement = (*DynamicForward)(nil)
	_ Statement = (*EscapeChar)(nil)
	_ Statement = (*ExitOnForwardFailure)(nil)
	_ Statement = (*FingerprintHash)(nil)
	_ Statement = (*ForwardX11)(nil)
	_ Statement = (*ForwardX11Timeout)(nil)
	_ Statement = (*ForwardX11Trusted)(nil)
	_ Statement = (*GatewayPorts)(nil)
	_ Statement = (*GlobalKnownHostsFile)(nil)
	_ Statement = (*GSSApiAuthentication)(nil)
	_ Statement = (*GSSApiDelegateCredentials)(nil)
	_ Statement = (*HashKnownHosts)(nil)
	_ Statement = (*HostBasedAuthentication)(nil)
	_ Statement = (*HostBasedKeyTypes)(nil)
	_ Statement = (*HostKeyAlgorithms)(nil)
	_ Statement = (*HostKeyAlias)(nil)
	_ Statement = (*IdentitiesOnly)(nil)
	_ Statement = (*IdentityAgent)(nil)
	_ Statement = (*IPQoS)(nil)
	_ Statement = (*KbdInteractiveAuthentication)(nil)
	_ Statement = (*KbdInteractiveDevices)(nil)
	_ Statement = (*LocalCommand)(nil)
	_ Statement = (*Macs)(nil)
	_ Statement = (*NoHostAuthentication)(nil)
	_ Statement = (*NumberOfPasswordPrompts)(nil)
	_ Statement = (*PasswordAuthentication)(nil)
	_ Statement = (*PermitLocalCommand)(nil)
	_ Statement = (*PCKS11Provider)(nil)
	_ Statement = (*PreferredAuthentications)(nil)
	_ Statement = (*ProxyJump)(nil)
	_ Statement = (*ProxyUserFDPass)(nil)
	_ Statement = (*PubkeyAcceptedKeyTypes)(nil)
	_ Statement = (*PubkeyAuthentication)(nil)
	_ Statement = (*RekeyLimit)(nil)
	_ Statement = (*RemoteCommand)(nil)
	_ Statement = (*RemoteForward)(nil)
	_ Statement = (*RequestTTY)(nil)
	_ Statement = (*SendEnv)(nil)
	_ Statement = (*SetEnv)(nil)
	_ Statement = (*StreamLocalBindMask)(nil)
	_ Statement = (*StreamLocalBindUnlink)(nil)
	_ Statement = (*TCPKeepAlive)(nil)
	_ Statement = (*Tunnel)(nil)
	_ Statement = (*TunnelDevice)(nil)
	_ Statement = (*UpdateHostKeys)(nil)
	_ Statement = (*VerifyHostKeyDNS)(nil)
	_ Statement = (*VisualHostKey)(nil)
	_ Statement = (*XAuthLocation)(nil)
	_ Statement = (*ControlPath)(nil)
	// _ Statement = (*MatchStatement)(nil)
)

// Node AST node
type Node interface {
	TokenLiteral() string
	String() string
}

// Statement ...
type Statement interface {
	Node
}

// SSHConfig data structure holds Host and Match blocks.
type SSHConfig struct {
	Statements []Statement
}

// TokenLiteral ...
func (p *SSHConfig) TokenLiteral() string {
	if len(p.Statements) > 0 {
		return p.Statements[0].TokenLiteral()
	}
	return ""

}

// String ...
func (p *SSHConfig) String() string {
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

// TokenLiteral ...
func (ls *HostStatement) TokenLiteral() string {
	return ls.Token.Literal
}

// String ...
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

// TokenLiteral ...
func (b *BlockStatement) TokenLiteral() string {
	return ""
}

// String ...
func (b *BlockStatement) String() string {
	var out bytes.Buffer
	for _, s := range b.Statements {
		out.WriteString(s.String())
	}
	return out.String()
}

// HostName hostname inside the Host block
type HostName struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (h HostName) TokenLiteral() string {
	return h.Token.Literal
}

// String ...
func (h HostName) String() string {
	var out bytes.Buffer
	out.WriteString(h.Value)
	return out.String()
}

// IdentityFile ...
type IdentityFile struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (i *IdentityFile) TokenLiteral() string {
	return i.Token.Literal
}

// String ...
func (i IdentityFile) String() string {
	var out bytes.Buffer
	out.WriteString(i.Value)
	return out.String()
}

// User ...
type User struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (u User) TokenLiteral() string {
	return u.Token.Literal
}

// String ...
func (u User) String() string {
	var out bytes.Buffer
	out.WriteString(u.Value)
	return out.String()
}

// Port ...
type Port struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (u Port) TokenLiteral() string {
	return u.Token.Literal
}

// String ...
func (u Port) String() string {
	var out bytes.Buffer
	out.WriteString(u.Value)
	return out.String()
}

// UseKeyChain ...
type UseKeyChain struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (u UseKeyChain) TokenLiteral() string {
	return u.Token.Literal
}

// String ...
func (u UseKeyChain) String() string {
	var out bytes.Buffer
	out.WriteString(u.Value)
	return out.String()
}

// AddKeysToAgent ...
type AddKeysToAgent struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (a AddKeysToAgent) TokenLiteral() string {
	return a.Token.Literal
}

// String ...
func (a AddKeysToAgent) String() string {
	var out bytes.Buffer
	out.WriteString(a.Value)
	return out.String()
}

// LocalForward ...
type LocalForward struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (l LocalForward) TokenLiteral() string {
	return l.Token.Literal
}

// String ...
func (l LocalForward) String() string {
	var out bytes.Buffer
	out.WriteString(l.Value)
	return out.String()
}

// ControlMaster ...
type ControlMaster struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (c ControlMaster) TokenLiteral() string {
	return c.Token.Literal
}

// String ...
func (c ControlMaster) String() string {
	var out bytes.Buffer
	out.WriteString(c.Value)
	return out.String()
}

// ControlPersist ...
type ControlPersist struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (c ControlPersist) TokenLiteral() string {
	return c.Token.Literal
}

func (c ControlPersist) String() string {
	var out bytes.Buffer
	out.WriteString(c.Value)
	return out.String()
}

// ServerAliveOption ...
type ServerAliveOption struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (s ServerAliveOption) TokenLiteral() string {
	return s.Token.Literal
}

// String ...
func (s ServerAliveOption) String() string {
	var out bytes.Buffer
	out.WriteString(s.Value)
	return out.String()
}

// Compression ...
type Compression struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (c Compression) TokenLiteral() string {
	return c.Token.Literal
}

// String ...
func (c Compression) String() string {
	var out bytes.Buffer
	out.WriteString(c.Value)
	return out.String()
}

// CompressionLevelStatement ...
type CompressionLevelStatement struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (c CompressionLevelStatement) TokenLiteral() string {
	return c.Token.Literal
}

// String ...
func (c CompressionLevelStatement) String() string {
	var out bytes.Buffer
	out.WriteString(c.Value)
	return out.String()
}

// UserKnownHostsFile ...
type UserKnownHostsFile struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (u UserKnownHostsFile) TokenLiteral() string {
	return u.Token.Literal
}

// String ...
func (u UserKnownHostsFile) String() string {
	var out bytes.Buffer
	out.WriteString(u.Value)
	return out.String()
}

// StrictHostKeyChecking ...
type StrictHostKeyChecking struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (s StrictHostKeyChecking) TokenLiteral() string {
	return s.Token.Literal
}

// String ...
func (s StrictHostKeyChecking) String() string {
	var out bytes.Buffer
	out.WriteString(s.Value)
	return out.String()
}

// ProxyCommand ...
type ProxyCommand struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (p ProxyCommand) TokenLiteral() string {
	return p.Token.Literal
}

// String ...
func (p ProxyCommand) String() string {
	var out bytes.Buffer
	out.WriteString(p.Value)
	return out.String()
}

// ForwardAgent ...
type ForwardAgent struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (f ForwardAgent) TokenLiteral() string {
	return f.Token.Literal
}

// String ...
func (f ForwardAgent) String() string {
	var out bytes.Buffer
	out.WriteString(f.Value)
	return out.String()
}

// LogLevelStatement ...
type LogLevelStatement struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (l LogLevelStatement) TokenLiteral() string {
	return l.Token.Literal
}

// String ...
func (l LogLevelStatement) String() string {
	var out bytes.Buffer
	out.WriteString(l.Value)
	return out.String()
}

// CanonicalizeFallbackLocal ...
type CanonicalizeFallbackLocal struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (c *CanonicalizeFallbackLocal) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (c *CanonicalizeFallbackLocal) String() string {
	panic("implement me")
}

// CanonicalizeHostname ...
type CanonicalizeHostname struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (c CanonicalizeHostname) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (c CanonicalizeHostname) String() string {
	panic("implement me")
}

// CanonicalizeMaxDots ...
type CanonicalizeMaxDots struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (c CanonicalizeMaxDots) TokenLiteral() string {
	panic("implement me")
}

// String
func (c CanonicalizeMaxDots) String() string {
	panic("implement me")
}

// CanonicalizePermittedCNames ...
type CanonicalizePermittedCNames struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (c CanonicalizePermittedCNames) TokenLiteral() string {
	return c.Token.Literal
}

// String ...
func (c CanonicalizePermittedCNames) String() string {
	var out bytes.Buffer
	out.WriteString(c.Value)
	return out.String()
}

// CASignatureAlgorithms ...
type CASignatureAlgorithms struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (c *CASignatureAlgorithms) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (c *CASignatureAlgorithms) String() string {
	panic("implement me")
}

// CertificateFile ...
type CertificateFile struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (c CertificateFile) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (c CertificateFile) String() string {
	panic("implement me")
}

// ChallengeAuthentication ...
type ChallengeAuthentication struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (c ChallengeAuthentication) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (c ChallengeAuthentication) String() string {
	panic("implement me")
}

// CheckHostIP ...
type CheckHostIP struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (c CheckHostIP) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (c CheckHostIP) String() string {
	panic("implement me")
}

// Ciphers ...
type Ciphers struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (c Ciphers) TokenLiteral() string {
	panic("implement me")
}

func (c Ciphers) String() string {
	panic("implement me")
}

// ClearAllForwardings ...
type ClearAllForwardings struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (c ClearAllForwardings) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (c ClearAllForwardings) String() string {
	panic("implement me")
}

// ConnectionAttempts ...
type ConnectionAttempts struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (c ConnectionAttempts) TokenLiteral() string {
	panic("implement me")
}

func (c ConnectionAttempts) String() string {
	panic("implement me")
}

// ConnectionTimeout ...
type ConnectionTimeout struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (c ConnectionTimeout) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (c ConnectionTimeout) String() string {
	panic("implement me")
}

// DynamicForward ...
type DynamicForward struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (d DynamicForward) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (d DynamicForward) String() string {
	panic("implement me")
}

// EscapeChar ...
type EscapeChar struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (e EscapeChar) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (e EscapeChar) String() string {
	panic("implement me")
}

// ExitOnForwardFailure ...
type ExitOnForwardFailure struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (e ExitOnForwardFailure) TokenLiteral() string {
	panic("implement me")
}

func (e ExitOnForwardFailure) String() string {
	panic("implement me")
}

// FingerprintHash ...
type FingerprintHash struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (f FingerprintHash) TokenLiteral() string {

	panic("implement me")
}

// String ...
func (f FingerprintHash) String() string {
	panic("implement me")
}

// ForwardX11 ...
type ForwardX11 struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (f ForwardX11) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (f ForwardX11) String() string {
	panic("implement me")
}

// ForwardX11Timeout ...
type ForwardX11Timeout struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (f ForwardX11Timeout) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (f ForwardX11Timeout) String() string {
	panic("implement me")
}

// ForwardX11Trusted ...
type ForwardX11Trusted struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (f ForwardX11Trusted) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (f ForwardX11Trusted) String() string {
	panic("implement me")
}

// GatewayPorts ...
type GatewayPorts struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (g GatewayPorts) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (g GatewayPorts) String() string {
	panic("implement me")
}

// GlobalKnownHostsFile ...
type GlobalKnownHostsFile struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (g GlobalKnownHostsFile) TokenLiteral() string {
	return g.Token.Literal
}

func (g GlobalKnownHostsFile) String() string {
	var out bytes.Buffer
	out.WriteString(g.Value)
	return out.String()
}

// GSSApiAuthentication ...
type GSSApiAuthentication struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (g GSSApiAuthentication) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (g GSSApiAuthentication) String() string {
	panic("implement me")
}

// GSSApiDelegateCredentials ...
type GSSApiDelegateCredentials struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (g GSSApiDelegateCredentials) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (g GSSApiDelegateCredentials) String() string {
	panic("implement me")
}

// HashKnownHosts ...
type HashKnownHosts struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (h HashKnownHosts) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (h HashKnownHosts) String() string {
	panic("implement me")
}

// HostBasedAuthentication ...
type HostBasedAuthentication struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (h HostBasedAuthentication) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (h HostBasedAuthentication) String() string {
	panic("implement me")
}

// HostBasedKeyTypes ...
type HostBasedKeyTypes struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (h HostBasedKeyTypes) TokenLiteral() string {
	return h.Token.Literal
}

func (h HostBasedKeyTypes) String() string {
	var out bytes.Buffer
	out.WriteString(h.Value)
	return out.String()
}

// HostKeyAlgorithms ...
type HostKeyAlgorithms struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (h HostKeyAlgorithms) TokenLiteral() string {
	return h.Token.Literal
}

// String ...
func (h HostKeyAlgorithms) String() string {
	var out bytes.Buffer
	out.WriteString(h.Value)
	return out.String()
}

// HostKeyAlias ...
type HostKeyAlias struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (h HostKeyAlias) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (h HostKeyAlias) String() string {
	panic("implement me")
}

// IdentitiesOnly ...
type IdentitiesOnly struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (i IdentitiesOnly) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (i IdentitiesOnly) String() string {
	panic("implement me")
}

// IdentityAgent ...
type IdentityAgent struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (i IdentityAgent) TokenLiteral() string {
	return i.Token.Literal
}

// String ...
func (i IdentityAgent) String() string {
	var out bytes.Buffer
	out.WriteString(i.Value)
	return out.String()
}

// IPQoS ...
type IPQoS struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (i IPQoS) TokenLiteral() string {
	return i.Token.Literal
}

// String ...
func (i IPQoS) String() string {
	var out bytes.Buffer
	out.WriteString(i.Value)
	return out.String()
}

// KbdInteractiveAuthentication ...
type KbdInteractiveAuthentication struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (k KbdInteractiveAuthentication) TokenLiteral() string {
	panic("implement me")
}

// String
func (k KbdInteractiveAuthentication) String() string {
	panic("implement me")
}

// KbdInteractiveDevices ...
type KbdInteractiveDevices struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (k KbdInteractiveDevices) TokenLiteral() string {
	return k.Token.Literal
}

// String
func (k KbdInteractiveDevices) String() string {
	var out bytes.Buffer
	out.WriteString(k.Value)
	return out.String()
}

// LocalCommand ...
type LocalCommand struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (l LocalCommand) TokenLiteral() string {
	return l.Token.Literal
}

// String ...
func (l LocalCommand) String() string {
	var out bytes.Buffer
	out.WriteString(l.Value)
	return out.String()
}

// Macs ...
type Macs struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (m Macs) TokenLiteral() string {
	return m.Token.Literal
}

// String ...
func (m Macs) String() string {
	var out bytes.Buffer
	out.WriteString(m.Value)
	return out.String()
}

// NoHostAuthentication ...
type NoHostAuthentication struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (n NoHostAuthentication) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (n NoHostAuthentication) String() string {
	panic("implement me")
}

// NumberOfPasswordPrompts ...
type NumberOfPasswordPrompts struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (n NumberOfPasswordPrompts) TokenLiteral() string {
	panic("implement me")
}

func (n NumberOfPasswordPrompts) String() string {
	panic("implement me")
}

// PasswordAuthentication ...
type PasswordAuthentication struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (p PasswordAuthentication) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (p PasswordAuthentication) String() string {
	panic("implement me")
}

// PermitLocalCommand ...
type PermitLocalCommand struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (p PermitLocalCommand) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (p PermitLocalCommand) String() string {
	panic("implement me")
}

// PCKS11Provider ...
type PCKS11Provider struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (p PCKS11Provider) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (p PCKS11Provider) String() string {
	panic("implement me")
}

// PreferredAuthentications ...
type PreferredAuthentications struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (p PreferredAuthentications) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (p PreferredAuthentications) String() string {
	panic("implement me")
}

// ProxyJump ...
type ProxyJump struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (p ProxyJump) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (p ProxyJump) String() string {
	panic("implement me")
}

// ProxyUserFDPass ...
type ProxyUserFDPass struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (p ProxyUserFDPass) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (p ProxyUserFDPass) String() string {
	panic("implement me")
}

// PubkeyAcceptedKeyTypes ...
type PubkeyAcceptedKeyTypes struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (p PubkeyAcceptedKeyTypes) TokenLiteral() string {
	return p.Token.Literal
}

// String ...
func (p PubkeyAcceptedKeyTypes) String() string {
	var out bytes.Buffer
	out.WriteString(p.Value)
	return out.String()
}

// PubkeyAuthentication ...
type PubkeyAuthentication struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (p PubkeyAuthentication) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (p PubkeyAuthentication) String() string {
	panic("implement me")
}

// RekeyLimit ...
type RekeyLimit struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (r RekeyLimit) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (r RekeyLimit) String() string {
	panic("implement me")
}

// RemoteCommand ...
type RemoteCommand struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (r RemoteCommand) TokenLiteral() string {
	return r.Token.Literal
}

// String ...
func (r RemoteCommand) String() string {
	var out bytes.Buffer
	out.WriteString(r.Value)
	return out.String()
}

// RemoteForward ...
type RemoteForward struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (r RemoteForward) TokenLiteral() string {
	return r.Token.Literal
}

// String ...
func (r RemoteForward) String() string {
	var out bytes.Buffer
	out.WriteString(r.Value)
	return out.String()
}

// RequestTTY ...
type RequestTTY struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (r RequestTTY) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (r RequestTTY) String() string {
	panic("implement me")
}

// SendEnv ...
type SendEnv struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (s SendEnv) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (s SendEnv) String() string {
	panic("implement me")
}

// SetEnv ...
type SetEnv struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (s SetEnv) TokenLiteral() string {
	return s.Token.Literal
}

// String ...
func (s SetEnv) String() string {
	var out bytes.Buffer
	out.WriteString(s.Value)
	return out.String()
}

// StreamLocalBindMask ...
type StreamLocalBindMask struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (s StreamLocalBindMask) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (s StreamLocalBindMask) String() string {
	panic("implement me")
}

// StreamLocalBindUnlink ...
type StreamLocalBindUnlink struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (s StreamLocalBindUnlink) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (s StreamLocalBindUnlink) String() string {
	panic("implement me")
}

// TCPKeepAlive ...
type TCPKeepAlive struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (t TCPKeepAlive) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (t TCPKeepAlive) String() string {
	panic("implement me")
}

// Tunnel ...
type Tunnel struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (t Tunnel) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (t Tunnel) String() string {
	panic("implement me")
}

// TunnelDevice ...
type TunnelDevice struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (t TunnelDevice) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (t TunnelDevice) String() string {
	panic("implement me")
}

// UpdateHostKeys ...
type UpdateHostKeys struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (u UpdateHostKeys) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (u UpdateHostKeys) String() string {
	panic("implement me")
}

// VerifyHostKeyDNS ...
type VerifyHostKeyDNS struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (v *VerifyHostKeyDNS) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (v *VerifyHostKeyDNS) String() string {
	panic("implement me")
}

// VisualHostKey ...
type VisualHostKey struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (v *VisualHostKey) TokenLiteral() string {
	panic("implement me")
}

// String ...
func (v *VisualHostKey) String() string {
	panic("implement me")
}

// XAuthLocation ...
type XAuthLocation struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (x *XAuthLocation) TokenLiteral() string {
	return x.Token.Literal
}

// String ...
func (x *XAuthLocation) String() string {
	var out bytes.Buffer
	out.WriteString(x.Value)
	return out.String()
}

// ControlPath ...
type ControlPath struct {
	Token token.Token
	Value string
}

// TokenLiteral ...
func (c ControlPath) TokenLiteral() string {
	return c.Token.Literal
}

// String ...
func (c ControlPath) String() string {
	var out bytes.Buffer
	out.WriteString(c.Value)
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
