package token

type TokenType string

const (
	ILLEGAL = "ILLEGAL"
	EOF     = "EOF"
	IDENT   = "IDENT"

	// Identifiers + literals
	Host  = "host"
	OriginalHost = "originalHost"

	HOST  = "Host"
	MATCH = "Match"
	STAR  = "*"
	COMMA = ","
	STRING = "STRING"
)

var keywords = map[string]TokenType{
	"Host":  HOST,
	"Match": MATCH,
	"host":  Host,
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
