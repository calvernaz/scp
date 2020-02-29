package lexer

import (
	"testing"

	"github.com/calvernaz/scp/token"
)

func TestNextToken(t *testing.T) {
	input := `Host *
Host weirdloop
`

	tests := []struct {
		expectedType    token.TokenType
		expectedLiteral string
	}{
		{token.HOST, "Host"},
		{token.STAR, "*"},
		{token.HOST, "Host"},
		{token.IDENT, "weirdloop"},
		{token.EOF, ""},
	}

	l := New(input)

	for i, tt := range tests {
		tok := l.NextToken()

		if tok.Type != tt.expectedType {
			t.Fatalf("tests[%d] wrong tokentype, expected=%q, got=%q", i, tt.expectedType, tok.Type)
		}

		if tok.Literal != tt.expectedLiteral {
			t.Fatalf("tests[%d] - wrong literal, expected=%q, got=%q", i, tt.expectedLiteral, tok.Literal)
		}
	}
}

func TestNextStringToken(t *testing.T) {
	input := `"foobar"
"foo bar"`

	tests := []struct {
		expectedType token.TokenType
		expectedLiteral string
	} {
		{ token.STRING, "foobar"},
		{ token.STRING, "foo bar"},
		{ token.EOF, ""},
	}

	l := New(input)

	for i, tt := range tests {
		tok := l.NextToken()

		if tok.Type != tt.expectedType {
			t.Fatalf("tests[%d] wrong tokentype, expected=%q, got=%q", i, tt.expectedType, tok.Type)
		}

		if tok.Literal != tt.expectedLiteral {
			t.Fatalf("tests[%d] - wrong literal, expected=%q, got=%q", i, tt.expectedLiteral, tok.Literal)
		}
	}

}
