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
	// Identifiers + literals
	HOST                     = "Host"
	MATCH                    = "Match"
	HOSTNAME                 = "HostName"
	IDENTITY_FILE            = "IdentityFile"
	USER                     = "User"
	PORT                     = "Port"
	USE_KEY_CHAIN            = "UseKeyChain"
	ADD_KEYS_TO_AGENT        = "AddKeysToAgent"
	LOCAL_FORWARD            = "LocalForward"
	CONTROL_MASTER           = "ControlMaster"
	CONTROL_PATH             = "ControlPath"
	CONTROL_PERSIST          = "ControlPersist"
	SERVER_ALIVE_INTERVAL    = "ServerAliveInterval"
	SERVER_ALIVE_COUNT_MAX   = "ServerAliveCountMax"
	COMPRESION               = "Compression"
	COMPRESSION_LEVEL        = "CompressionLevel"
	STRICT_HOST_KEY_CHECKING = "StrictHostKeyChecking"
	PROXY_COMMAND            = "ProxyCommand"
	USER_KNOWN_HOSTS_FILE    = "UserKnownHostsFile"
	FORWARD_AGENT            = "ForwardAgent"
	LOG_LEVEL                = "LogLevel"
	STAR                     = "*"
	COMMA                    = ","
	HASH                     = "#"
)

var keywords = map[string]TokenType{
	"host":                  HOST,
	"hostname":              HOSTNAME,
	"match":                 MATCH,
	"identityfile":          IDENTITY_FILE,
	"user":                  USER,
	"port":                  PORT,
	"usekeychain":           USE_KEY_CHAIN,
	"addkeystoagent":        ADD_KEYS_TO_AGENT,
	"localforward":          LOCAL_FORWARD,
	"controlmaster":         CONTROL_MASTER,
	"controlpath":           CONTROL_PATH,
	"controlpersist":        CONTROL_PERSIST,
	"serveraliveinterval":   SERVER_ALIVE_INTERVAL,
	"serveralivecountmax":   SERVER_ALIVE_COUNT_MAX,
	"compression":           COMPRESION,
	"compressionlevel":      COMPRESSION_LEVEL,
	"stricthostkeychecking": STRICT_HOST_KEY_CHECKING,
	"proxycommand":          PROXY_COMMAND,
	"userknownhostsfile":    USER_KNOWN_HOSTS_FILE,
	"forwardagent":          FORWARD_AGENT,
	"loglevel":              LOG_LEVEL,
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
