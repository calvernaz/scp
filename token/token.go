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
	HOST              = "Host"
	MATCH             = "Match"
	HOSTNAME          = "HostName"
	IDENTITY_FILE     = "IdentityFile"
	USER              = "User"
	PORT              = "Port"
	USE_KEY_CHAIN     = "UseKeyChain"
	ADD_KEYS_TO_AGENT = "AddKeysToAgent"
	LOCAL_FORWARD     = "LocalForward"
	STAR              = "*"
	COMMA             = ","
)

var keywords = map[string]TokenType{
	"host":           HOST,
	"hostname":       HOSTNAME,
	"match":          MATCH,
	"identityfile":   IDENTITY_FILE,
	"user":           USER,
	"port":           PORT,
	"usekeychain":    USE_KEY_CHAIN,
	"addkeystoagent": ADD_KEYS_TO_AGENT,
	"localforward":   LOCAL_FORWARD,
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
