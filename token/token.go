package token

type TokenType string

const (
	ILLEGAL = "ILLEGAL"
	EOF     = "EOF"
	IDENT   = "IDENT"

	// Identifiers + literals
	HOST  = "Host"
	MATCH = "Match"
	STAR  = "*"
	COMMA = ","
)

var keywords = map[string]TokenType{
	"Host":  HOST,
	"Match": MATCH,
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
