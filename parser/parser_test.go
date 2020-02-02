package parser

import (
	"testing"

	"ssh-client-parser/ast"
	"ssh-client-parser/lexer"
)

func TestConfigStatement(t *testing.T) {
	input := `Host *`

	l := lexer.New(input)
	p := New(l)

	program := p.ParseProgram()
	if program == nil {
		t.Fatalf("ParseProgram() return nil")
	}

	if len(program.Statements) != 1 {
		t.Fatalf("program.Statements does not contain 3 statements. got=%d", len(program.Statements))
	}

	tests := []struct {
		expectedString string
	}{
		{
			"Host",
		},
	}

	for i, tt := range tests {
		stmt := program.Statements[i]
		if !testConfigStatement(t, stmt, tt.expectedString) {
			return
		}
	}
}

func testConfigStatement(t *testing.T, s ast.Statement, name string) bool {
	if s.TokenLiteral() != "Host" {
		t.Errorf("s.TokenLiteral not 'Host'. got=%q", s.TokenLiteral())
	}

	configStmt, ok := s.(*ast.ConfigStatement)
	if !ok {
		t.Errorf("s not *ast.ConfigStatement. got=%T", s)
		return false
	}

	if configStmt.Name.Literal != name {
		t.Errorf("configStmt.Name not '%s'. got=%s", name, configStmt.Name)
		return false
	}

	if configStmt.TokenLiteral() != name {
		t.Errorf("configStmt.TokenLiteral() not '%s'. got=%s", name, configStmt.TokenLiteral())
		return false
	}

	return true
}
