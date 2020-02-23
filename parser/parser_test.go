package parser

import (
	"io/ioutil"
	"os"
	"testing"

	"ssh-client-parser/ast"
	"ssh-client-parser/lexer"
)

//func TestMatchStatement(t *testing.T) {
//	input := `Match host "some-domain.com"`
//
//	l := lexer.New(input)
//	p := New(l)
//
//	program := p.ParseConfig()
//	if program == nil {
//		t.Fatalf("ParseConfig() return nil")
//	}
//
//	if len(program.Statements) != 1 {
//		t.Fatalf("program.Statements does not contain 1 statement. got=%d", len(program.Statements))
//	}
//
//	tests := []struct {
//		expectedString string
//	}{
//		{"Match"},
//	}
//
//	for i, tt := range tests {
//		stmt := program.Statements[i]
//		if !testMatchConfigStatement(t, stmt, tt.expectedString) {
//			return
//		}
//	}
//}

//func testMatchConfigStatement(t *testing.T, s ast.Statement, name string) bool {
//	if s.TokenLiteral() != "Match" {
//		t.Errorf("s.TokenLiteral not 'Match'. got=%q", s.TokenLiteral())
//	}
//
//	configStmt, ok := s.(*ast.MatchStatement)
//	if !ok {
//		t.Errorf("s not *ast.ConfigStatement. got=%T", s)
//		return false
//	}
//
//	if configStmt.Token.Literal != name {
//		t.Errorf("configStmt.Name not '%s'. got=%s", name, configStmt.Token)
//		return false
//	}
//
//	if configStmt.TokenLiteral() != name {
//		t.Errorf("configStmt.TokenLiteral() not '%s'. got=%s", name, configStmt.TokenLiteral())
//		return false
//	}
//
//	if configStmt.Condition != "host" {
//		t.Errorf("configStmt.Condition not '%s'. got=%s", "host", configStmt.Condition)
//		return false
//	}
//
//	return true
//}

func TestSshConfig(t *testing.T) {
	file, err := os.Open("testdata/ssh_config")
	if err != nil {
		t.FailNow()
	}

	input, err := ioutil.ReadAll(file)
	if err != nil {
		t.FailNow()
	}

	l := lexer.New(string(input))
	p := New(l)
	program := p.ParseConfig()
	checkParserErrors(t, p)

	if len(program.Statements) != 1 {
		t.Fatalf("program does not contain %d statements. got=%d\n", 1, len(program.Statements))
	}

	stmt, ok := program.Statements[0].(*ast.HostStatement)
	if !ok {
		t.Fatalf("program.Statements[0] is not ast.HostStatement. got=%T", program.Statements[0])
	}

	blockStmt := stmt.Statement
	if len(blockStmt.Statements) != 1 {
		t.Fatalf("program does not contain %d block statements. got=%d\n", 1, len(stmt.Statement.Statements))
	}

	hostnameStmt, ok := blockStmt.Statements[0].(*ast.HostNameStatement)
	if !ok {
		t.Fatalf("blockStatement.statment[0] is not HostNameStatement. got=%T", hostnameStmt)
	}
}

func TestHostBlockStatement(t *testing.T) {
	input := `Host "some-domain.com"
    HostName server.com
    IdentityFile "/Users/calvernaz/.ssh/Sydney_SSH_Access.pem"
    UseKeyChain yes
    AddKeysToAgent yes
    LocalForward 127.0.0.1:27012 127.0.0.1:27012
    User ec2-user
    Port 22
`
	l := lexer.New(input)
	p := New(l)
	program := p.ParseConfig()
	checkParserErrors(t, p)

	if len(program.Statements) != 1 {
		t.Fatalf("program does not contain %d statements. got=%d\n", 1, len(program.Statements))
	}

	stmt, ok := program.Statements[0].(*ast.HostStatement)
	if !ok {
		t.Fatalf("program.Statements[0] is not ast.HostStatement. got=%T", program.Statements[0])
	}

	blockStmt := stmt.Statement
	if len(blockStmt.Statements) != 1 {
		t.Fatalf("program does not contain %d block statements. got=%d\n", 1, len(stmt.Statement.Statements))
	}

	hostnameStmt, ok := blockStmt.Statements[0].(*ast.HostNameStatement)
	if !ok {
		t.Fatalf("blockStatement.statment[0] is not HostNameStatement. got=%T", hostnameStmt)
	}
}

func checkParserErrors(t *testing.T, p *Parser) {
	errors := p.Errors()

	if len(errors) == 0 {
		return
	}

	t.Errorf("parser has %d errors", len(errors))
	for _, msg := range errors {
		t.Errorf("parser error: %q", msg)
	}
	t.FailNow()
}

func TestHostStatement(t *testing.T) {
	input := `Host *`

	l := lexer.New(input)
	p := New(l)

	program := p.ParseConfig()
	if program == nil {
		t.Fatalf("ParseConfig() return nil")
	}

	if len(program.Statements) != 1 {
		t.Fatalf("program.Statements does not contain 1 statements. got=%d", len(program.Statements))
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
		if !testHostConfigStatement(t, stmt, tt.expectedString) {
			return
		}
	}
}

func testHostConfigStatement(t *testing.T, s ast.Statement, name string) bool {
	if s.TokenLiteral() != "Host" {
		t.Errorf("s.TokenLiteral not 'Host'. got=%q", s.TokenLiteral())
	}

	configStmt, ok := s.(*ast.HostStatement)
	if !ok {
		t.Errorf("s not *ast.ConfigStatement. got=%T", s)
		return false
	}

	if configStmt.Token.Literal != name {
		t.Errorf("configStmt.Name not '%s'. got=%s", name, configStmt.Token)
		return false
	}

	if configStmt.TokenLiteral() != name {
		t.Errorf("configStmt.TokenLiteral() not '%s'. got=%s", name, configStmt.TokenLiteral())
		return false
	}

	return true
}
