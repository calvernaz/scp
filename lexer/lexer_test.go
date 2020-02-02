package lexer

import (
	"testing"

	"ssh-client-parser/token"
)

func TestNextToken(t *testing.T) {
	input := `Host *`

	tests := []struct {
		expectedType    token.TokenType
		expectedLiteral string
	}{
		{token.HOST, "Host"},
		{token.STAR, "*"},
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
