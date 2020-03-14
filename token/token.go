package token

import (
	"strings"
)

type TokenType string

const (
	ILLEGAL = "ILLEGAL"
	EOF     = "EOF"
	IDENT   = "IDENT"
	STRING  = "STRING"
	INT     = "INT"
	STAR    = "*"
	COMMA   = ","
	HASH    = "#"

	ADD_KEYS_TO_AGENT                    = "AddKeysToAgent"
	ADDRESS_FAMILY                       = "AddressFamily"
	BATCH_MODE                           = "BatchMode"
	BIND_ADDRESS                         = "BindAddress"
	CANONICAL_DOMAINS                    = "CanonicalDomains"
	CANONICALIZE_FALLBACK_LOCAL          = "CanonicalizeFallbackLocal"
	CANONICALIZE_HOSTNAME                = "CanonicalizeHostname"
	CANONICALIZE_MAX_DOTS                = "CanonicalizeMaxDots"
	CANONICALIZE_PERMITTED_CNAMES        = "CanonicalizePermittedCNAMEs"
	CA_SIGNATURE_ALGORITHMS              = "CASignatureAlgorithms"
	CERTIFICATE_FILE                     = "CertificateFile"
	CHALLENGE_RESPONSE_AUTHENTICATION    = "ChallengeResponseAuthentication"
	CHECK_HOST_IP                        = "CheckHostIP"
	CIPHERS                              = "Ciphers"
	CLEAR_ALL_FORWARDINGS                = "ClearAllForwardings"
	COMPRESION                           = "Compression"
	CONNECTION_ATTEMPTS                  = "ConnectionAttempts"
	CONNECTION_TIMEOUT                   = "ConnectionTimeout"
	CONTROL_MASTER                       = "ControlMaster"
	CONTROL_PATH                         = "ControlPath"
	CONTROL_PERSIST                      = "ControlPersist"
	DYNAMIC_FORWARD                      = "DynamicForward"
	ESCAPE_CHAR                          = "EscapeChar"
	EXIT_ON_FORWARD_FAILURE              = "ExitOnForwardFailure"
	FINGERPRINT_HASH                     = "FingerprintHash"
	FORWARD_AGENT                        = "ForwardAgent"
	FORWARD_X11                          = "ForwardX11"
	FORWARD_X11_TIMEOUT                  = "ForwardX11Timeout"
	FORWARD_X11_TRUSTED                  = "ForwardX11Trusted"
	GATEWAY_PORTS                        = "GatewayPorts"
	GLOBAL_KNOWN_HOSTS_FILE              = "GlobalKnownHostsFile"
	GSSAPI_AUTHENTICATION                = "GSSAPIAuthentication"
	GSSAPI_DELEGATE_CREDENTIALS          = "GSSAPIDeleteCredentials"
	HASH_KNOWN_HOSTS                     = "HashKnownHosts"
	HOST                                 = "Host"
	HOSTBASED_AUTHENTICATION             = "HostbasedAuthentication"
	HOSTBASED_KEY_TYPES                  = "HostbasedKeyTypes"
	HOSTBASED_KEY_ALGORITHMS             = "HostKeyAlgorithms"
	HOST_KEY_ALIAS                       = "HostKeyAlias"
	HOSTNAME                             = "HostName"
	IDENTITIES_ONLY                      = "IdentitiesOnly"
	IDENTITY_AGENT                       = "IdentityAgent"
	IDENTITY_FILE                        = "IdentityFile"
	IP_QOS                               = "IPQoS"
	KBD_INTERACTIVE_AUTHENTICATION       = "KbdInteractiveAuthentication"
	KBD_INTERACTIVE_DEVICES              = "KbdInteractiveDevices"
	KEX_ALGORITHMS                       = "KexAlgorithms"
	LOCAL_COMMAND                        = "LocalCommand"
	LOCAL_FORWARD                        = "LocalForward"
	LOG_LEVEL                            = "LogLevel"
	MACS                                 = "MACs"
	MATCH                                = "Match"
	NO_HOST_AUTHENTICATION_FOR_LOCALHOST = "NoHostAuthenticationForLocalhost"
	NUMBER_OF_PASSWORD_PROMPTS           = "NumberOfPasswordPrompts"
	PASSWORD_AUTHENTICATION              = "PasswordAuthentication"
	PERMIT_LOCAL_COMMAND                 = "PermitLocalCommand"
	PCKS11_PROVIDER                      = "PKCS11Provider"
	PORT                                 = "Port"
	PREFERRED_AUTHENTICATIONS            = "PreferredAuthentications"
	PROXY_COMMAND                        = "ProxyCommand"
	PROXY_JUMP                           = "ProxyJump"
	PROXY_USE_FDPASS                     = "ProxyUseFdpass"
	PUBKEY_ACCEPTED_KEY_TYPES            = "PubkeyAcceptedKeyTypes"
	PUBKEY_AUTHENTICATION                = "PubkeyAuthentication"
	REKEY_LIMIT                          = "RekeyLimit"
	REMOTE_COMMAND                       = "RemoteCommand"
	REMOTE_FORWARD                       = "RemoteForward"
	REQUEST_TTY                          = "RequestTTY"
	SEND_ENV                             = "SendEnv"
	SERVER_ALIVE_INTERVAL                = "ServerAliveInterval"
	SERVER_ALIVE_COUNT_MAX               = "ServerAliveCountMax"
	SET_ENV                              = "SetEnv"
	STREAM_LOCAL_BIND_MASK               = "StreamLocalBindMask"
	STREAM_LOCAL_BIND_UNLINK             = "StreamLocalBindUnlink"
	STRICT_HOST_KEY_CHECKING             = "StrictHostKeyChecking"
	TCP_KEEP_ALINE                       = "TCPKeepAlive"
	TUNNEL                               = "Tunnel"
	TUNNEL_DEVICE                        = "TunnelDevice"
	UPDATE_HOST_KEYS                     = "UpdateHostKeys"
	USE_KEY_CHAIN                        = "UseKeyChain"
	USER                                 = "User"
	USER_KNOWN_HOSTS_FILE                = "UserKnownHostsFile"
	VERIFY_HOST_KEY_DNS                  = "VerifyHostKeyDNS"
	VISUAL_HOST_KEY                      = "VisualHostKey"
	XAUTH_LOCATION                       = "XAuthLocation"
)

var keywords = map[string]TokenType{
	"addkeystoagent":        ADD_KEYS_TO_AGENT,
	"addressfamily":         ADDRESS_FAMILY,
	"batchmode":             BATCH_MODE,
	"bindaddress":           BIND_ADDRESS,
	"host":                  HOST,
	"hostname":              HOSTNAME,
	"match":                 MATCH,
	"identityfile":          IDENTITY_FILE,
	"user":                  USER,
	"port":                  PORT,
	"usekeychain":           USE_KEY_CHAIN,
	"localforward":          LOCAL_FORWARD,
	"controlmaster":         CONTROL_MASTER,
	"controlpath":           CONTROL_PATH,
	"controlpersist":        CONTROL_PERSIST,
	"serveraliveinterval":   SERVER_ALIVE_INTERVAL,
	"serveralivecountmax":   SERVER_ALIVE_COUNT_MAX,
	"compression":           COMPRESION,
	"stricthostkeychecking": STRICT_HOST_KEY_CHECKING,
	"proxycommand":          PROXY_COMMAND,
	"userknownhostsfile":    USER_KNOWN_HOSTS_FILE,
	"forwardagent":          FORWARD_AGENT,
	"loglevel":              LOG_LEVEL,
	"canonicaldomains": CANONICAL_DOMAINS,
}

func LookupIndent(ident string) TokenType {
	if tok, ok := keywords[strings.ToLower(ident)]; ok {
		return tok
	}
	return IDENT
}

type Token struct {
	Type    TokenType
	Literal string
}
