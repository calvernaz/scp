package lexer

import (
	"github.com/calvernaz/scp/token"
)

type Lexer struct {
	input        string
	position     int
	readPosition int
	ch           byte
}

func New(input string) *Lexer {
	l := &Lexer{input: input}
	l.readChar()
	return l
}

func (l *Lexer) NextToken() token.Token {
	var tok token.Token

start:
	l.skipWhitespace()

	switch l.ch {
	case ',':
		tok = newToken(token.COMMA, l.ch)
	case 0:
		tok.Literal = ""
		tok.Type = token.EOF
	default:
		if isIdentifier(l.ch) {
			tok.Literal = l.readIdentifier()
			tok.Type = token.LookupIndent(tok.Literal)
			return tok
		} else if isString(l.ch) {
			tok.Literal = l.readString()
			tok.Type = token.LookupIndent(tok.Literal)
		} else if isComment(l.ch) {
			l.skipComments()
			goto start
			//if isLetter(l.ch) || isExtraCharacter(l.ch) {
			//} else if isDigit(l.ch) {
			//	tok.Type = token.INT
			//	tok.Literal = l.readNumber()
		} else {
			tok = newToken(token.ILLEGAL, l.ch)
		}
	}
	l.readChar()
	return tok
}

func isIdentifier(ch byte) bool {
	return isLetter(ch) || isDigit(ch) || isExtraCharacter(ch)
}

func (l *Lexer) skipWhitespace() {
	for l.ch == ' ' || l.ch == '\t' || l.ch == '\n' || l.ch == '\r' {
		l.readChar()
	}
}

func (l *Lexer) skipComments() {
	for {
		l.readChar()
		if l.ch == '\n' || l.ch == '\r' {
			break
		}
	}
}

func (l *Lexer) readIdentifier() string {
	position := l.position
	for isLetter(l.ch) || isDigit(l.ch) || isExtraCharacter(l.ch) {
		l.readChar()
	}
	return l.input[position:l.position]
}

func (l *Lexer) readChar() {
	if l.readPosition >= len(l.input) {
		l.ch = 0
	} else {
		l.ch = l.input[l.readPosition]
	}
	l.position = l.readPosition
	l.readPosition += 1
}

func (l *Lexer) readString() string {
	position := l.position + 1
	for {
		l.readChar()
		if l.ch == '"' || l.ch == 0 {
			break
		}
	}
	return l.input[position:l.position]
}

func isLetter(ch byte) bool {
	return 'a' <= ch && ch <= 'z' || 'A' <= ch && ch <= 'Z'
}

func isExtraCharacter(ch byte) bool {
	return ch == '/' || ch == '_' || ch == '.' || ch == '-' || ch ==
		'+' || ch == '~' || ch == '@' || ch == '%' || ch == ':' || ch == '&' || ch == '=' || ch == '*' || ch == '?'
}

func isString(ch byte) bool {
	return ch == '"'
}

func isComment(ch byte) bool {
	return ch == '#'
}

func (l *Lexer) readNumber() string {
	position := l.position
	for isDigit(l.ch) {
		l.readChar()
	}
	return l.input[position:l.position]
}

func (l *Lexer) Input() string {
	return l.input
}

func isDigit(ch byte) bool {
	return '0' <= ch && ch <= '9' || ch == '.' || ch == ':'
}

func newToken(tokenType token.TokenType, ch byte) token.Token {
	return token.Token{Type: tokenType, Literal: string(ch)}
}

