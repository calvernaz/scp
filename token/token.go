package token

import (
	"strings"
)

// Type token type
type Type string

// Constants ...
const (
	Illegal                          = "Illegal"
	EOF                              = "EOF"
	Ident                            = "Ident"
	Comma                            = ","
	AddKeysToAgent                   = "AddKeysToAgent"
	AddressFamily                    = "AddressFamily"
	BatchMode                        = "BatchMode"
	BindAddress                      = "BindAddress"
	CanonicalDomains                 = "CanonicalDomains"
	CanonicalizeFallbackLocal        = "CanonicalizeFallbackLocal"
	CanonicalizeHostname             = "CanonicalizeHostname"
	CanonicalizeMaxDots              = "CanonicalizeMaxDots"
	CanonicalizePermittedCnames      = "CanonicalizePermittedCNAMEs"
	CaSignatureAlgorithms            = "CASignatureAlgorithms"
	CertificateFile                  = "CertificateFile"
	ChallengeResponseAuthentication  = "ChallengeResponseAuthentication"
	CheckHostIP                      = "CheckHostIP"
	Ciphers                          = "Ciphers"
	ClearAllForwardings              = "ClearAllForwardings"
	Compression                      = "Compression"
	CompressionLevel                 = "CompressionLevel"
	ConnectionAttempts               = "ConnectionAttempts"
	ConnectionTimeout                = "ConnectionTimeout"
	ControlMaster                    = "ControlMaster"
	ControlPath                      = "ControlPath"
	ControlPersist                   = "ControlPersist"
	DynamicForward                   = "DynamicForward"
	EscapeChar                       = "EscapeChar"
	ExitOnForwardFailure             = "ExitOnForwardFailure"
	FingerprintHash                  = "FingerprintHash"
	ForwardAgent                     = "ForwardAgent"
	ForwardX11                       = "ForwardX11"
	ForwardX11Timeout                = "ForwardX11Timeout"
	ForwardX11Trusted                = "ForwardX11Trusted"
	GatewayPorts                     = "GatewayPorts"
	GlobalKnownHostsFile             = "GlobalKnownHostsFile"
	GSSAPIAuthentication             = "GSSAPIAuthentication"
	GSSAPIDelegateCredentials        = "GSSAPIDelegateCredentials"
	HashKnownHosts                   = "HashKnownHosts"
	Host                             = "Host"
	HostbasedAuthentication          = ""
	HostbasedKeyTypes                = "HostbasedKeyTypes"
	HostbasedKeyAlgorithms           = "HostKeyAlgorithms"
	HostKeyAlias                     = "HostKeyAlias"
	Hostname                         = "HostName"
	IdentitiesOnly                   = "IdentitiesOnly"
	IdentityAgent                    = "IdentityAgent"
	IdentityFile                     = "IdentityFile"
	IPQoS                            = "IPQoS"
	KbdInteractiveAuthentication     = "KbdInteractiveAuthentication"
	KbdInteractiveDevices            = "KbdInteractiveDevices"
	HostKeyAlgorithms                = "HostKeyAlgorithms"
	LocalCommand                     = "LocalCommand"
	LocalForward                     = "LocalForward"
	LogLevel                         = "LogLevel"
	Macs                             = "MACs"
	Match                            = "Match"
	NoHostAuthenticationForLocalhost = "NoHostAuthenticationForLocalhost"
	NumberOfPasswordPrompts          = "NumberOfPasswordPrompts"
	PasswordAuthentication           = "PasswordAuthentication"
	PermitLocalCommand               = "PermitLocalCommand"
	Pkcs11Provider                   = "PKCS11Provider"
	Port                             = "Port"
	PreferredAuthentications         = "PreferredAuthentications"
	ProxyCommand                     = "ProxyCommand"
	ProxyJump                        = "ProxyJump"
	ProxyUseFdpass                   = "ProxyUseFdpass"
	PubkeyAcceptedKeyTypes           = "PubkeyAcceptedKeyTypes"
	PubkeyAuthentication             = "PubkeyAuthentication"
	RekeyLimit                       = "RekeyLimit"
	RemoteCommand                    = "RemoteCommand"
	RemoteForward                    = "RemoteForward"
	RequestTty                       = "RequestTTY"
	SendEnv                          = "SendEnv"
	ServerAliveInterval              = "ServerAliveInterval"
	ServerAliveCountMax              = "ServerAliveCountMax"
	SetEnv                           = "SetEnv"
	StreamLocalBindMask              = "StreamLocalBindMask"
	StreamLocalBindUnlink            = "StreamLocalBindUnlink"
	StrictHostKeyChecking            = "StrictHostKeyChecking"
	TCPKeepAlive                     = "TCPKeepAlive"
	Tunnel                           = "Tunnel"
	TunnelDevice                     = "TunnelDevice"
	UpdateHostKeys                   = "UpdateHostKeys"
	UseKeyChain                      = "UseKeyChain"
	User                             = "User"
	UserKnownHostsFile               = "UserKnownHostsFile"
	VerifyHostKeyDNS                 = "VerifyHostKeyDNS"
	VisualHostKey                    = "VisualHostKey"
	XauthLocation                    = "XAuthLocation"
	Include                          = "Include"
	All                              = "All"
	Canonical                        = "Canonical"
	Final                            = "Final"
	Exec                             = "Exec"
	String                           = "String"
	OriginalHost                     = "OriginalHost"
)

var keywords = map[string]Type{
	"addkeystoagent":                   AddKeysToAgent,
	"addressfamily":                    AddressFamily,
	"batchmode":                        BatchMode,
	"bindaddress":                      BindAddress,
	"canonicaldomains":                 CanonicalDomains,
	"canonicalizefallbacklocal":        CanonicalizeFallbackLocal,
	"canonicalizehostname":             CanonicalizeHostname,
	"canonicalizemaxdots":              CanonicalizeMaxDots,
	"canonicalizepermittedcnames":      CanonicalizePermittedCnames,
	"casignaturealgorithms":            CaSignatureAlgorithms,
	"certificatefile":                  CertificateFile,
	"challengeresponseauthentication":  ChallengeResponseAuthentication,
	"checkhostip":                      CheckHostIP,
	"ciphers":                          Ciphers,
	"clearallforwardings":              ClearAllForwardings,
	"compression":                      Compression,
	"compressionlevel":                 CompressionLevel,
	"connectionattempts":               ConnectionAttempts,
	"connectiontimeout":                ConnectionTimeout,
	"controlmaster":                    ControlMaster,
	"controlpath":                      ControlPath,
	"controlpersist":                   ControlPersist,
	"dynamicforward":                   DynamicForward,
	"escapechar":                       EscapeChar,
	"exitonforwardfailure":             ExitOnForwardFailure,
	"fingerprinthash":                  FingerprintHash,
	"forwardagent":                     ForwardAgent,
	"forwardx11":                       ForwardX11,
	"forwardx11timeout":                ForwardX11Timeout,
	"forwardx11trusted":                ForwardX11Trusted,
	"gatewayports":                     GatewayPorts,
	"globalknownhostsfile":             GlobalKnownHostsFile,
	"gssapiauthentication":             GSSAPIAuthentication,
	"gssapideletecredentials":          GSSAPIDelegateCredentials,
	"hashknownhosts":                   HashKnownHosts,
	"host":                             Host,
	"hostbasedauthentication":          HostbasedAuthentication,
	"hostbasedkeytypes":                HostbasedKeyTypes,
	"hostkeyalias":                     HostKeyAlias,
	"hostname":                         Hostname,
	"identitiesonly":                   IdentitiesOnly,
	"identityagent":                    IdentityAgent,
	"identityfile":                     IdentityFile,
	"ipqos":                            IPQoS,
	"kbdinteractiveauthentication":     KbdInteractiveAuthentication,
	"kbdinteractivedevices":            KbdInteractiveDevices,
	"hostkeyalgorithms":                HostKeyAlgorithms,
	"localcommand":                     LocalCommand,
	"localforward":                     LocalForward,
	"loglevel":                         LogLevel,
	"macs":                             Macs,
	"nohostauthenticationforlocalhost": NoHostAuthenticationForLocalhost,
	"numberofpasswordprompts":          NumberOfPasswordPrompts,
	"passwordauthentication":           PasswordAuthentication,
	"permitlocalcommand":               PermitLocalCommand,
	"pkcs11provider":                   Pkcs11Provider,
	"port":                             Port,
	"preferredauthentications":         PreferredAuthentications,
	"proxycommand":                     ProxyCommand,
	"proxyjump":                        ProxyJump,
	"proxyusefdpass":                   ProxyUseFdpass,
	"pubkeyacceptedkeytypes":           PubkeyAcceptedKeyTypes,
	"pubkeyauthentication":             PubkeyAuthentication,
	"rekeylimit":                       RekeyLimit,
	"remotecommand":                    RemoteCommand,
	"remoteforward":                    RemoteForward,
	"requesttty":                       RequestTty,
	"sendenv":                          SendEnv,
	"serveraliveinterval":              ServerAliveInterval,
	"serveralivecountmax":              ServerAliveCountMax,
	"setenv":                           SetEnv,
	"streamlocalbindmask":              StreamLocalBindMask,
	"streamlocalbindunlink":            StreamLocalBindUnlink,
	"stricthostkeychecking":            StrictHostKeyChecking,
	"tcpkeepalive":                     TCPKeepAlive,
	"tunnel":                           Tunnel,
	"tunneldevice":                     TunnelDevice,
	"updatehostkeys":                   UpdateHostKeys,
	"usekeychain":                      UseKeyChain,
	"user":                             User,
	"userknownhostsfile":               UserKnownHostsFile,
	"verifyhostkeydns":                 VerifyHostKeyDNS,
	"visualhostkey":                    VisualHostKey,
	"xauthlocation":                    XauthLocation,
	"match":                            Match,
	"include":                          Include,
	"all":                              All,
	"canonical":                        Canonical,
	"final":                            Final,
	"exec":                             Exec,
	"string":                           String,
	"originalhost":                     OriginalHost,
}

// LookupIndent ...
func LookupIndent(ident string) Type {
	if tok, ok := keywords[strings.ToLower(ident)]; ok {
		return tok
	}
	return Ident
}

// Token ...
type Token struct {
	Type    Type
	Literal string
}
