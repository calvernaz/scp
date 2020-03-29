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
	_ Statement = (*ServerAliveOptionStatement)(nil)
	_ Statement = (*CompressionStatement)(nil)
	_ Statement = (*CompressionLevelStatement)(nil)
	_ Statement = (*UserKnownHostsFileStatement)(nil)
	_ Statement = (*StrictHostKeyCheckingStatement)(nil)
	_ Statement = (*ProxyCommandStatement)(nil)
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
	_ Statement = (*ClearAllForwarding)(nil)
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
	_ Statement = (*KeyAlgorithms)(nil)
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
	_ Statement = (*TcpKeepAlive)(nil)
	_ Statement = (*Tunnel)(nil)
	_ Statement = (*TunnelDevice)(nil)
	_ Statement = (*UpdateHostKeys)(nil)
	_ Statement = (*VerifyHostKeyDNS)(nil)
	_ Statement = (*VisualHostKey)(nil)
	// _ Statement = (*MatchStatement)(nil)
)

type Node interface {
	TokenLiteral() string
	String() string
}

type Statement interface {
	Node
}

// SshConfig data structure holds Host and Match blocks.
type SshConfig struct {
	Statements []Statement
}

func (p *SshConfig) TokenLiteral() string {
	if len(p.Statements) > 0 {
		return p.Statements[0].TokenLiteral()
	} else {
		return ""
	}
}
func (p *SshConfig) String() string {
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

func (ls *HostStatement) TokenLiteral() string {
	return ls.Token.Literal
}
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

func (b *BlockStatement) TokenLiteral() string {
	return ""
}
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

func (h HostName) TokenLiteral() string {
	return h.Token.Literal
}
func (h HostName) String() string {
	var out bytes.Buffer
	out.WriteString(h.Value)
	return out.String()
}

// IdentityFile
type IdentityFile struct {
	Token token.Token
	Value string
}

func (i *IdentityFile) TokenLiteral() string {
	return i.Token.Literal
}
func (i IdentityFile) String() string {
	var out bytes.Buffer
	out.WriteString(i.Value)
	return out.String()
}

// User
type User struct {
	Token token.Token
	Value string
}

func (u User) TokenLiteral() string {
	return u.Token.Literal
}
func (u User) String() string {
	var out bytes.Buffer
	out.WriteString(u.Value)
	return out.String()
}

// Port
type Port struct {
	Token token.Token
	Value string
}

func (u Port) TokenLiteral() string {
	return u.Token.Literal
}
func (u Port) String() string {
	var out bytes.Buffer
	out.WriteString(u.Value)
	return out.String()
}

// UseKeyChain
type UseKeyChain struct {
	Token token.Token
	Value string
}

func (u UseKeyChain) TokenLiteral() string {
	return u.Token.Literal
}

func (u UseKeyChain) String() string {
	var out bytes.Buffer
	out.WriteString(u.Value)
	return out.String()
}

type AddKeysToAgent struct {
	Token token.Token
	Value string
}

func (a AddKeysToAgent) TokenLiteral() string {
	return a.Token.Literal
}

func (a AddKeysToAgent) String() string {
	var out bytes.Buffer
	out.WriteString(a.Value)
	return out.String()
}

type LocalForward struct {
	Token token.Token
	Value string
}

func (l LocalForward) TokenLiteral() string {
	return l.Token.Literal
}

func (l LocalForward) String() string {
	var out bytes.Buffer
	out.WriteString(l.Value)
	return out.String()
}


type ControlMaster struct {
	Token token.Token
	Value string
}

func (c ControlMaster) TokenLiteral() string {
	return c.Token.Literal
}

func (c ControlMaster) String() string {
	var out bytes.Buffer
	out.WriteString(c.Value)
	return out.String()
}

type ControlPersist struct {
	Token token.Token
	Value string
}

func (c ControlPersist) TokenLiteral() string {
	return c.Token.Literal
}

func (c ControlPersist) String() string {
	var out bytes.Buffer
	out.WriteString(c.Value)
	return out.String()
}

type ServerAliveOptionStatement struct {
	Token token.Token
	Value string
}

func (s ServerAliveOptionStatement) TokenLiteral() string {
	return s.Token.Literal
}

func (s ServerAliveOptionStatement) String() string {
	var out bytes.Buffer
	out.WriteString(s.Value)
	return out.String()
}

type CompressionStatement struct {
	Token token.Token
	Value string
}

func (c CompressionStatement) TokenLiteral() string {
	return c.Token.Literal
}

func (c CompressionStatement) String() string {
	var out bytes.Buffer
	out.WriteString(c.Value)
	return out.String()
}

type CompressionLevelStatement struct {
	Token token.Token
	Value string
}

func (c CompressionLevelStatement) TokenLiteral() string {
	return c.Token.Literal
}

func (c CompressionLevelStatement) String() string {
	var out bytes.Buffer
	out.WriteString(c.Value)
	return out.String()
}

type UserKnownHostsFileStatement struct {
	Token token.Token
	Value string
}

func (u UserKnownHostsFileStatement) TokenLiteral() string {
	return u.Token.Literal
}

func (u UserKnownHostsFileStatement) String() string {
	var out bytes.Buffer
	out.WriteString(u.Value)
	return out.String()
}

type StrictHostKeyCheckingStatement struct {
	Token token.Token
	Value string
}

func (s StrictHostKeyCheckingStatement) TokenLiteral() string {
	return s.Token.Literal
}

func (s StrictHostKeyCheckingStatement) String() string {
	var out bytes.Buffer
	out.WriteString(s.Value)
	return out.String()
}

type ProxyCommandStatement struct {
	Token token.Token
	Value string
}

func (p ProxyCommandStatement) TokenLiteral() string {
	return p.Token.Literal
}

func (p ProxyCommandStatement) String() string {
	var out bytes.Buffer
	out.WriteString(p.Value)
	return out.String()
}

type ForwardAgent struct {
	Token token.Token
	Value string
}

func (f ForwardAgent) TokenLiteral() string {
	return f.Token.Literal
}

func (f ForwardAgent) String() string {
	var out bytes.Buffer
	out.WriteString(f.Value)
	return out.String()
}

type LogLevelStatement struct {
	Token token.Token
	Value string
}

func (l LogLevelStatement) TokenLiteral() string {
	return l.Token.Literal
}

func (l LogLevelStatement) String() string {
	var out bytes.Buffer
	out.WriteString(l.Value)
	return out.String()
}

type CanonicalizeFallbackLocal struct {
	Token token.Token
	Value string
}

func (c *CanonicalizeFallbackLocal) TokenLiteral() string {
	panic("implement me")
}

func (c *CanonicalizeFallbackLocal) String() string {
	panic("implement me")
}

type CanonicalizeHostname struct {
	Token token.Token
	Value string
}

func (c CanonicalizeHostname) TokenLiteral() string {
	panic("implement me")
}

func (c CanonicalizeHostname) String() string {
	panic("implement me")
}

type CanonicalizeMaxDots struct {
	Token token.Token
	Value string
}

func (c CanonicalizeMaxDots) TokenLiteral() string {
	panic("implement me")
}

func (c CanonicalizeMaxDots) String() string {
	panic("implement me")
}

type CanonicalizePermittedCNames struct {
	Token token.Token
	Value string
}

func (c CanonicalizePermittedCNames) TokenLiteral() string {
	panic("implement me")
}

func (c CanonicalizePermittedCNames) String() string {
	panic("implement me")
}

type CASignatureAlgorithms struct {
	Token token.Token
	Value string
}

func (c *CASignatureAlgorithms) TokenLiteral() string {
	panic("implement me")
}

func (c *CASignatureAlgorithms) String() string {
	panic("implement me")
}

type CertificateFile struct {
	Token token.Token
	Value string
}

func (c CertificateFile) TokenLiteral() string {
	panic("implement me")
}

func (c CertificateFile) String() string {
	panic("implement me")
}


type ChallengeAuthentication struct {
	Token token.Token
	Value string
}

func (c ChallengeAuthentication) TokenLiteral() string {
	panic("implement me")
}

func (c ChallengeAuthentication) String() string {
	panic("implement me")
}

type CheckHostIP struct {
	Token token.Token
	Value string
}

func (c CheckHostIP) TokenLiteral() string {
	panic("implement me")
}

func (c CheckHostIP) String() string {
	panic("implement me")
}

type Ciphers struct {
	Token token.Token
	Value string
}

func (c Ciphers) TokenLiteral() string {
	panic("implement me")
}

func (c Ciphers) String() string {
	panic("implement me")
}

type ClearAllForwarding struct {
	Token token.Token
	Value string
}

func (c ClearAllForwarding) TokenLiteral() string {
	panic("implement me")
}

func (c ClearAllForwarding) String() string {
	panic("implement me")
}

type ConnectionAttempts struct {
	Token token.Token
	Value string
}

func (c ConnectionAttempts) TokenLiteral() string {
	panic("implement me")
}

func (c ConnectionAttempts) String() string {
	panic("implement me")
}

type ConnectionTimeout struct {
	Token token.Token
	Value string
}

func (c ConnectionTimeout) TokenLiteral() string {
	panic("implement me")
}

func (c ConnectionTimeout) String() string {
	panic("implement me")
}


type DynamicForward struct {
	Token token.Token
	Value string
}

func (d DynamicForward) TokenLiteral() string {
	panic("implement me")
}

func (d DynamicForward) String() string {
	panic("implement me")
}

type EscapeChar struct {
	Token token.Token
	Value string
}

func (e EscapeChar) TokenLiteral() string {
	panic("implement me")
}

func (e EscapeChar) String() string {
	panic("implement me")
}


type ExitOnForwardFailure struct {
	Token token.Token
	Value string
}

func (e ExitOnForwardFailure) TokenLiteral() string {
	panic("implement me")
}

func (e ExitOnForwardFailure) String() string {
	panic("implement me")
}

type FingerprintHash struct {
	Token token.Token
	Value string
}

func (f FingerprintHash) TokenLiteral() string {

panic("implement me")
}

func (f FingerprintHash) String() string {
	panic("implement me")
}


type ForwardX11 struct {
	Token token.Token
	Value string
}

func (f ForwardX11) TokenLiteral() string {
	panic("implement me")
}

func (f ForwardX11) String() string {
	panic("implement me")
}

type ForwardX11Timeout struct {
	Token token.Token
	Value string
}

func (f ForwardX11Timeout) TokenLiteral() string {
	panic("implement me")
}

func (f ForwardX11Timeout) String() string {
	panic("implement me")
}


type ForwardX11Trusted struct {
	Token token.Token
	Value string
}

func (f ForwardX11Trusted) TokenLiteral() string {
	panic("implement me")
}

func (f ForwardX11Trusted) String() string {
	panic("implement me")
}

type GatewayPorts struct {
	Token token.Token
	Value string
}

func (g GatewayPorts) TokenLiteral() string {
	panic("implement me")
}

func (g GatewayPorts) String() string {
	panic("implement me")
}

type GlobalKnownHostsFile struct {
	Token token.Token
	Value string
}

func (g GlobalKnownHostsFile) TokenLiteral() string {
	return g.Token.Literal
}

func (g GlobalKnownHostsFile) String() string {
	var out bytes.Buffer
	out.WriteString(g.Value)
	return out.String()
}

type GSSApiAuthentication struct {
	Token token.Token
	Value string
}

func (g GSSApiAuthentication) TokenLiteral() string {
	panic("implement me")
}

func (g GSSApiAuthentication) String() string {
	panic("implement me")
}


type GSSApiDelegateCredentials struct {
	Token token.Token
	Value string
}

func (g GSSApiDelegateCredentials) TokenLiteral() string {
	panic("implement me")
}

func (g GSSApiDelegateCredentials) String() string {
	panic("implement me")
}

type HashKnownHosts struct {
	Token token.Token
	Value string
}

func (h HashKnownHosts) TokenLiteral() string {
	panic("implement me")
}

func (h HashKnownHosts) String() string {
	panic("implement me")
}

type HostBasedAuthentication struct {
	Token token.Token
	Value string
}

func (h HostBasedAuthentication) TokenLiteral() string {
	panic("implement me")
}

func (h HostBasedAuthentication) String() string {
	panic("implement me")
}

type HostBasedKeyTypes struct {
	Token token.Token
	Value string
}

func (h HostBasedKeyTypes) TokenLiteral() string {
	return h.Token.Literal
}

func (h HostBasedKeyTypes) String() string {
	var out bytes.Buffer
	out.WriteString(h.Value)
	return out.String()
}

type HostKeyAlgorithms struct {
	Token token.Token
	Value string
}

func (h HostKeyAlgorithms) TokenLiteral() string {
	return h.Token.Literal
}

func (h HostKeyAlgorithms) String() string {
	var out bytes.Buffer
	out.WriteString(h.Value)
	return out.String()
}

type HostKeyAlias struct {
	Token token.Token
	Value string
}

func (h HostKeyAlias) TokenLiteral() string {
	panic("implement me")
}

func (h HostKeyAlias) String() string {
	panic("implement me")
}

type IdentitiesOnly struct {
	Token token.Token
	Value string
}

func (i IdentitiesOnly) TokenLiteral() string {
	panic("implement me")
}

func (i IdentitiesOnly) String() string {
	panic("implement me")
}

type IdentityAgent struct {
	Token token.Token
	Value string
}

func (i IdentityAgent) TokenLiteral() string {
	panic("implement me")
}

func (i IdentityAgent) String() string {
	panic("implement me")
}

type IPQoS struct {
	Token token.Token
	Value string
}

func (i IPQoS) TokenLiteral() string {
	panic("implement me")
}

func (i IPQoS) String() string {
	panic("implement me")
}

type KbdInteractiveAuthentication struct {
	Token token.Token
	Value string
}

func (k KbdInteractiveAuthentication) TokenLiteral() string {
	panic("implement me")
}

func (k KbdInteractiveAuthentication) String() string {
	panic("implement me")
}


type KbdInteractiveDevices struct {
	Token token.Token
	Value string
}

func (k KbdInteractiveDevices) TokenLiteral() string {
	panic("implement me")
}

func (k KbdInteractiveDevices) String() string {
	panic("implement me")
}

type KeyAlgorithms struct {
	Token token.Token
	Value string
}

func (k KeyAlgorithms) TokenLiteral() string {
	panic("implement me")
}

func (k KeyAlgorithms) String() string {
	panic("implement me")
}

type LocalCommand struct {
	Token token.Token
	Value string
}

func (l LocalCommand) TokenLiteral() string {
	panic("implement me")
}

func (l LocalCommand) String() string {
	panic("implement me")
}

type Macs struct {
	Token token.Token
	Value string
}

func (m Macs) TokenLiteral() string {
	panic("implement me")
}

func (m Macs) String() string {
	panic("implement me")
}


type NoHostAuthentication struct {
	Token token.Token
	Value string
}

func (n NoHostAuthentication) TokenLiteral() string {
	panic("implement me")
}

func (n NoHostAuthentication) String() string {
	panic("implement me")
}

type NumberOfPasswordPrompts struct {
	Token token.Token
	Value string
}

func (n NumberOfPasswordPrompts) TokenLiteral() string {
	panic("implement me")
}

func (n NumberOfPasswordPrompts) String() string {
	panic("implement me")
}

type PasswordAuthentication struct {
	Token token.Token
	Value string
}

func (p PasswordAuthentication) TokenLiteral() string {
	panic("implement me")
}

func (p PasswordAuthentication) String() string {
	panic("implement me")
}

type PermitLocalCommand struct {
	Token token.Token
	Value string
}

func (p PermitLocalCommand) TokenLiteral() string {
	panic("implement me")
}

func (p PermitLocalCommand) String() string {
	panic("implement me")
}

type PCKS11Provider struct {
	Token token.Token
	Value string
}

func (p PCKS11Provider) TokenLiteral() string {
	panic("implement me")
}

func (p PCKS11Provider) String() string {
	panic("implement me")
}

type PreferredAuthentications struct {
	Token token.Token
	Value string
}

func (p PreferredAuthentications) TokenLiteral() string {
	panic("implement me")
}

func (p PreferredAuthentications) String() string {
	panic("implement me")
}

type ProxyJump struct {
	Token token.Token
	Value string
}

func (p ProxyJump) TokenLiteral() string {
	panic("implement me")
}

func (p ProxyJump) String() string {
	panic("implement me")
}

type ProxyUserFDPass struct {
	Token token.Token
	Value string
}

func (p ProxyUserFDPass) TokenLiteral() string {
	panic("implement me")
}

func (p ProxyUserFDPass) String() string {
	panic("implement me")
}

type PubkeyAcceptedKeyTypes struct {
	Token token.Token
	Value string
}

func (p PubkeyAcceptedKeyTypes) TokenLiteral() string {
	panic("implement me")
}

func (p PubkeyAcceptedKeyTypes) String() string {
	panic("implement me")
}


type PubkeyAuthentication struct {
	Token token.Token
	Value string
}

func (p PubkeyAuthentication) TokenLiteral() string {
	panic("implement me")
}

func (p PubkeyAuthentication) String() string {
	panic("implement me")
}

type RekeyLimit struct {
	Token token.Token
	Value string
}

func (r RekeyLimit) TokenLiteral() string {
	panic("implement me")
}

func (r RekeyLimit) String() string {
	panic("implement me")
}

type RemoteCommand struct {
	Token token.Token
	Value string
}

func (r RemoteCommand) TokenLiteral() string {
	panic("implement me")
}

func (r RemoteCommand) String() string {
	panic("implement me")
}

type RemoteForward struct {
	Token token.Token
	Value string
}

func (r RemoteForward) TokenLiteral() string {
	panic("implement me")
}

func (r RemoteForward) String() string {
	panic("implement me")
}

type RequestTTY struct {
	Token token.Token
	Value string
}

func (r RequestTTY) TokenLiteral() string {
	panic("implement me")
}

func (r RequestTTY) String() string {
	panic("implement me")
}

type SendEnv struct {
	Token token.Token
	Value string
}

func (s SendEnv) TokenLiteral() string {
	panic("implement me")
}

func (s SendEnv) String() string {
	panic("implement me")
}

type SetEnv struct {
	Token token.Token
	Value string
}

func (s SetEnv) TokenLiteral() string {
	panic("implement me")
}

func (s SetEnv) String() string {
	panic("implement me")
}

type StreamLocalBindMask struct {
	Token token.Token
	Value string
}

func (s StreamLocalBindMask) TokenLiteral() string {
	panic("implement me")
}

func (s StreamLocalBindMask) String() string {
	panic("implement me")
}

type StreamLocalBindUnlink struct {
	Token token.Token
	Value string
}

func (s StreamLocalBindUnlink) TokenLiteral() string {
	panic("implement me")
}

func (s StreamLocalBindUnlink) String() string {
	panic("implement me")
}

type TcpKeepAlive struct {
	Token token.Token
	Value string
}

func (t TcpKeepAlive) TokenLiteral() string {
	panic("implement me")
}

func (t TcpKeepAlive) String() string {
	panic("implement me")
}

type Tunnel struct {
	Token token.Token
	Value string
}

func (t Tunnel) TokenLiteral() string {
	panic("implement me")
}

func (t Tunnel) String() string {
	panic("implement me")
}

type TunnelDevice struct {
	Token token.Token
	Value string
}

func (t TunnelDevice) TokenLiteral() string {
	panic("implement me")
}

func (t TunnelDevice) String() string {
	panic("implement me")
}

type UpdateHostKeys struct {
	Token token.Token
	Value string
}

func (u UpdateHostKeys) TokenLiteral() string {
	panic("implement me")
}

func (u UpdateHostKeys) String() string {
	panic("implement me")
}

type VerifyHostKeyDNS struct {
	Token token.Token
	Value string
}

func (v *VerifyHostKeyDNS) TokenLiteral() string {
	panic("implement me")
}

func (v *VerifyHostKeyDNS) String() string {
	panic("implement me")
}

type VisualHostKey struct {
	Token token.Token
	Value string
}

func (v *VisualHostKey) TokenLiteral() string {
	panic("implement me")
}

func (v *VisualHostKey) String() string {
	panic("implement me")
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
