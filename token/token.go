package token

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
	"Host":           HOST,
	"HostName":       HOSTNAME,
	"Match":          MATCH,
	"IdentityFile":   IDENTITY_FILE,
	"User":           USER,
	"Port":           PORT,
	"UseKeyChain":    USE_KEY_CHAIN,
	"AddKeysToAgent": ADD_KEYS_TO_AGENT,
	"LocalForward":   LOCAL_FORWARD,
}

func LookupIndent(ident string) TokenType {
	if tok, ok := keywords[ident]; ok {
		return tok
	}
	return IDENT
}

type Token struct {
	Type    TokenType
	Literal string
}
