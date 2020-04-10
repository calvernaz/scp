package token

import (
	"strings"
)

type TokenType string

const (
	ILLEGAL = "ILLEGAL"
	EOF     = "EOF"
	IDENT   = "IDENT"
	STAR    = "*"
	COMMA   = ","

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
	COMPRESSION                          = "Compression"
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
	GSSAPI_DELEGATE_CREDENTIALS          = "GSSAPIDelegateCredentials"
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
	HOST_KEY_ALGORITHMS                  = "HostKeyAlgorithms"
	LOCAL_COMMAND                        = "LocalCommand"
	LOCAL_FORWARD                        = "LocalForward"
	LOG_LEVEL                            = "LogLevel"
	MACS                                 = "MACs"
	MATCH                                = "Match"
	NO_HOST_AUTHENTICATION_FOR_LOCALHOST = "NoHostAuthenticationForLocalhost"
	NUMBER_OF_PASSWORD_PROMPTS           = "NumberOfPasswordPrompts"
	PASSWORD_AUTHENTICATION              = "PasswordAuthentication"
	PERMIT_LOCAL_COMMAND                 = "PermitLocalCommand"
	PKCS11_PROVIDER                      = "PKCS11Provider"
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
	TCP_KEEP_ALIVE                       = "TCPKeepAlive"
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
	"addkeystoagent":                   ADD_KEYS_TO_AGENT,
	"addressfamily":                    ADDRESS_FAMILY,
	"batchmode":                        BATCH_MODE,
	"bindaddress":                      BIND_ADDRESS,
	"canonicaldomains":                 CANONICAL_DOMAINS,
	"canonicalizefallbacklocal":        CANONICALIZE_FALLBACK_LOCAL,
	"canonicalizehostname":             CANONICALIZE_HOSTNAME,
	"canonicalizemaxdots":              CANONICALIZE_MAX_DOTS,
	"canonicalizepermittedcnames":      CANONICALIZE_PERMITTED_CNAMES,
	"casignaturealgorithms":            CA_SIGNATURE_ALGORITHMS,
	"certificatefile":                  CERTIFICATE_FILE,
	"challengeresponseauthentication":  CHALLENGE_RESPONSE_AUTHENTICATION,
	"checkhostip":                      CHECK_HOST_IP,
	"ciphers":                          CIPHERS,
	"clearallforwardings":              CLEAR_ALL_FORWARDINGS,
	"compression":                      COMPRESSION,
	"connectionattempts":               CONNECTION_ATTEMPTS,
	"connectiontimeout":                CONNECTION_TIMEOUT,
	"controlmaster":                    CONTROL_MASTER,
	"controlpath":                      CONTROL_PATH,
	"controlpersist":                   CONTROL_PERSIST,
	"dynamicforward":                   DYNAMIC_FORWARD,
	"escapechar":                       ESCAPE_CHAR,
	"exitonforwardfailure":             EXIT_ON_FORWARD_FAILURE,
	"fingerprinthash":                  FINGERPRINT_HASH,
	"forwardagent":                     FORWARD_AGENT,
	"forwardx11":                       FORWARD_X11,
	"forwardx11timeout":                FORWARD_X11_TIMEOUT,
	"forwardx11trusted":                FORWARD_X11_TRUSTED,
	"gatewayports":                     GATEWAY_PORTS,
	"globalknownhostsfile":             GLOBAL_KNOWN_HOSTS_FILE,
	"gssapiauthentication":             GSSAPI_AUTHENTICATION,
	"gssapideletecredentials":          GSSAPI_DELEGATE_CREDENTIALS,
	"hashknownhosts":                   HASH_KNOWN_HOSTS,
	"host":                             HOST,
	"hostbasedauthentication":          HOSTBASED_AUTHENTICATION,
	"hostbasedkeytypes":                HOSTBASED_KEY_TYPES,
	"hostkeyalias":                     HOST_KEY_ALIAS,
	"hostname":                         HOSTNAME,
	"identitiesonly":                   IDENTITIES_ONLY,
	"identityagent":                    IDENTITY_AGENT,
	"identityfile":                     IDENTITY_FILE,
	"ipqos":                            IP_QOS,
	"kbdinteractiveauthentication":     KBD_INTERACTIVE_AUTHENTICATION,
	"kbdinteractivedevices":            KBD_INTERACTIVE_DEVICES,
	"hostkeyalgorithms":                HOST_KEY_ALGORITHMS,
	"localcommand":                     LOCAL_COMMAND,
	"localforward":                     LOCAL_FORWARD,
	"loglevel":                         LOG_LEVEL,
	"macs":                             MACS,
	"nohostauthenticationforlocalhost": NO_HOST_AUTHENTICATION_FOR_LOCALHOST,
	"numberofpasswordprompts":          NUMBER_OF_PASSWORD_PROMPTS,
	"passwordauthentication":           PASSWORD_AUTHENTICATION,
	"permitlocalcommand":               PERMIT_LOCAL_COMMAND,
	"pkcs11provider":                   PKCS11_PROVIDER,
	"port":                             PORT,
	"preferredauthentications":         PREFERRED_AUTHENTICATIONS,
	"proxycommand":                     PROXY_COMMAND,
	"proxyjump":                        PROXY_JUMP,
	"proxyusefdpass":                   PROXY_USE_FDPASS,
	"pubkeyacceptedkeytypes":           PUBKEY_ACCEPTED_KEY_TYPES,
	"pubkeyauthentication":             PUBKEY_AUTHENTICATION,
	"rekeylimit":                       REKEY_LIMIT,
	"remotecommand":                    REMOTE_COMMAND,
	"remoteforward":                    REMOTE_FORWARD,
	"requesttty":                       REQUEST_TTY,
	"sendenv":                          SEND_ENV,
	"serveraliveinterval":              SERVER_ALIVE_INTERVAL,
	"serveralivecountmax":              SERVER_ALIVE_COUNT_MAX,
	"setenv":                           SET_ENV,
	"streamlocalbindmask":              STREAM_LOCAL_BIND_MASK,
	"streamlocalbindunlink":            STREAM_LOCAL_BIND_UNLINK,
	"stricthostkeychecking":            STRICT_HOST_KEY_CHECKING,
	"tcpkeepalive":                     TCP_KEEP_ALIVE,
	"tunnel":                           TUNNEL,
	"tunneldevice":                     TUNNEL_DEVICE,
	"updatehostkeys":                   UPDATE_HOST_KEYS,
	"usekeychain":                      USE_KEY_CHAIN,
	"user":                             USER,
	"userknownhostsfile":               USER_KNOWN_HOSTS_FILE,
	"verifyhostkeydns":                 VERIFY_HOST_KEY_DNS,
	"visualhostkey":                    VISUAL_HOST_KEY,
	"xauthlocation":                    XAUTH_LOCATION,
	"match":                            MATCH,
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
