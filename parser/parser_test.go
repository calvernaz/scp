package parser

import (
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"github.com/calvernaz/scp/ast"
	"github.com/calvernaz/scp/lexer"
	"github.com/calvernaz/scp/token"
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
//	configStmt, ok := s.(*ast.Match)
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

	if len(program.Statements) != 25 {
		t.Fatalf("program does not contain %d statements. got=%d\n", 25, len(program.Statements))
	}
}

func TestSshConfig2(t *testing.T) {
	file, err := os.Open("testdata/config")
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

	if len(program.Statements) != 11 {
		t.Fatalf("program does not contain %d statements. got=%d\n", 11, len(program.Statements))
	}

	for _, stmt := range program.Statements {
		if hostStmt, ok := stmt.(*ast.HostStatement); ok {
			for _, blockStmt := range hostStmt.Statement.Statements {
				if identityStmt, ok := blockStmt.(*ast.IdentityFile); ok {
					if identityStmt.Value == "" {
						t.Fatal("identity is empty")
					}
				}
			}
		}
	}
}

func TestHostBlockStatement(t *testing.T) {
	input := `Host "some-domain.com"
    HostName server.com
    IdentityFile "/Users/user/.ssh/key.pem"
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
	if len(blockStmt.Statements) != 7 {
		t.Fatalf("program does not contain %d block statements. got=%d\n", 7, len(stmt.Statement.Statements))
	}

	hostnameStmt, ok := blockStmt.Statements[0].(*ast.HostName)
	if !ok {
		t.Fatalf("blockStatement.statment[0] is not HostName. got=%T", hostnameStmt)
	}
}

func TestIncorrectHostStatement(t *testing.T) {
	input := `Host Host 10.217.198.*
  ProxyCommand sh -c "~/.ssh/hostmatch.py %h %p"
  IdentityFile ~/.ssh/key.key
  StrictHostKeyChecking no
  User ec2-user`

	l := lexer.New(input)
	p := New(l)
	p.ParseConfig()

	if len(p.errors) < 1 {
		t.Fatalf("expected errors, got %d", len(p.errors))
	}
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

func TestParserValidation(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "Host Host 10.217.198.*",
			want:  "failed to parse host statement: line %d at position %d",
		},
		{
			input: "Host",
			want:  "failed to parse host statement: line %d at position %d",
		},
	}

	for _, tt := range tests {
		l := lexer.New(tt.input)
		p := New(l)

		t.Run(tt.input, func(t *testing.T) {
			if got := p.parseStatement(); len(p.errors) == 0 {
				t.Errorf("parseStatement() = %q, want %q", got, tt.want)
			} else {
				line, pos := p.l.Position()
				want := fmt.Sprintf(tt.want, line, pos)
				if !reflect.DeepEqual(p.errors[0], want) {
					t.Errorf("parseStatement() = %q, want %q", p.errors[0], want)
				}
			}
		})
	}
}

func TestParser_parseStatement(t *testing.T) {

	tests := []struct {
		input string
		want  ast.Statement
	}{
		{
			input: "HostName host1.example.com",
			want: &ast.HostName{
				Token: token.Token{
					Type:    token.Hostname,
					Literal: "HostName",
				},
				Value: "host1.example.com",
			},
		},
		{
			input: "IdentityFile ~/.ssh/key_name_for_github",
			want: &ast.IdentityFile{
				Token: token.Token{
					Type:    token.IdentityFile,
					Literal: "IdentityFile",
				},
				Value: "~/.ssh/key_name_for_github",
			},
		},
		{
			input: "User user1",
			want: &ast.User{
				Token: token.Token{
					Type:    token.User,
					Literal: "User",
				},
				Value: "user1",
			},
		},
		{
			input: "Port 22",
			want: &ast.Port{
				Token: token.Token{
					Type:    token.Port,
					Literal: "Port",
				},
				Value: "22",
			},
		},
		{
			input: "UseKeyChain yes",
			want: &ast.UseKeyChain{
				Token: token.Token{
					Type:    token.UseKeyChain,
					Literal: "UseKeyChain",
				},
				Value: "yes",
			},
		},
		{
			input: "AddKeysToAgent yes",
			want: &ast.AddKeysToAgent{
				Token: token.Token{
					Type:    token.AddKeysToAgent,
					Literal: "AddKeysToAgent",
				},
				Value: "yes",
			},
		},
		{
			input: "LocalForward 8443 127.0.0.1:443",
			want: &ast.LocalForward{
				Token: token.Token{
					Type:    token.LocalForward,
					Literal: "LocalForward",
				},
				Value: "8443 127.0.0.1:443",
			},
		},
		{
			input: "ControlMaster yes",
			want: &ast.ControlMaster{
				Token: token.Token{
					Type:    token.ControlMaster,
					Literal: "ControlMaster",
				},
				Value: "yes",
			},
		},
		{
			input: "ControlPersist no",
			want: &ast.ControlPersist{
				Token: token.Token{
					Type:    token.ControlPersist,
					Literal: "ControlPersist",
				},
				Value: "no",
			},
		},
		{
			input: "DynamicForward localhost:3333",
			want: &ast.DynamicForward{
				Token: token.Token{
					Type:    token.DynamicForward,
					Literal: "DynamicForward",
				},
				Value: "localhost:3333",
			},
		},
		{
			input: "EscapeChar ~",
			want: &ast.EscapeChar{
				Token: token.Token{
					Type:    token.EscapeChar,
					Literal: "EscapeChar",
				},
				Value: "~",
			},
		},
		{
			input: "ExitOnForwardFailure yes",
			want: &ast.ExitOnForwardFailure{
				Token: token.Token{
					Type:    token.ExitOnForwardFailure,
					Literal: "ExitOnForwardFailure",
				},
				Value: "yes",
			},
		},
		{
			input: "FingerprintHash sha256",
			want: &ast.FingerprintHash{
				Token: token.Token{
					Type:    token.FingerprintHash,
					Literal: "FingerprintHash",
				},
				Value: "sha256",
			},
		},
		{
			input: "ForwardAgent yes",
			want: &ast.ForwardAgent{
				Token: token.Token{
					Type:    token.ForwardAgent,
					Literal: "ForwardAgent",
				},
				Value: "yes",
			},
		},
		{
			input: "ForwardX11Timeout 0",
			want: &ast.ForwardX11Timeout{
				Token: token.Token{
					Type:    token.ForwardX11Timeout,
					Literal: "ForwardX11Timeout",
				},
				Value: "0",
			},
		},
		{
			input: "ForwardX11Trusted yes",
			want: &ast.ForwardX11Trusted{
				Token: token.Token{
					Type:    token.ForwardX11Trusted,
					Literal: "ForwardX11Trusted",
				},
				Value: "yes",
			},
		},
		{
			input: "GatewayPorts yes",
			want: &ast.GatewayPorts{
				Token: token.Token{
					Type:    token.GatewayPorts,
					Literal: "GatewayPorts",
				},
				Value: "yes",
			},
		},
		{
			input: "GlobalKnownHostsFile /etc/ssh/ssh_known_hosts, /etc/ssh/ssh_known_hosts2, /etc/ssh/ssh_known_hosts3",
			want: &ast.GlobalKnownHostsFile{
				Token: token.Token{
					Type:    token.GlobalKnownHostsFile,
					Literal: "GlobalKnownHostsFile",
				},
				Value: "/etc/ssh/ssh_known_hosts, /etc/ssh/ssh_known_hosts2, /etc/ssh/ssh_known_hosts3",
			},
		},
		{
			input: "GSSAPIAuthentication yes",
			want: &ast.GSSApiAuthentication{
				Token: token.Token{
					Type:    token.GSSAPIAuthentication,
					Literal: "GSSAPIAuthentication",
				},
				Value: "yes",
			},
		},
		{
			input: "GSSAPIDeleteCredentials yes",
			want: &ast.GSSApiDelegateCredentials{
				Token: token.Token{
					Type:    token.GSSAPIDelegateCredentials,
					Literal: "GSSAPIDeleteCredentials",
				},
				Value: "yes",
			},
		},
		{
			input: "HashKnownHosts yes",
			want: &ast.HashKnownHosts{
				Token: token.Token{
					Type:    token.HashKnownHosts,
					Literal: "HashKnownHosts",
				},
				Value: "yes",
			},
		},
		{
			input: "HostbasedAuthentication yes",
			want: &ast.HostBasedAuthentication{
				Token: token.Token{
					Type:    token.HostbasedAuthentication,
					Literal: "HostbasedAuthentication",
				},
				Value: "yes",
			},
		},
		{
			input: "HostbasedKeyTypes ecdsa-sha2-nistp256-cert-v01@openssh.com, ecdsa-sha2-nistp384-cert-v01@openssh.com",
			want: &ast.HostBasedKeyTypes{
				Token: token.Token{
					Type:    token.HostbasedKeyTypes,
					Literal: "HostbasedKeyTypes",
				},
				Value: "ecdsa-sha2-nistp256-cert-v01@openssh.com, ecdsa-sha2-nistp384-cert-v01@openssh.com",
			},
		},
		{
			input: "HostKeyAlgorithms ecdsa-sha2-nistp256-cert-v01@openssh.com, ecdsa-sha2-nistp384-cert-v01@openssh.com",
			want: &ast.HostKeyAlgorithms{
				Token: token.Token{
					Type:    token.HostbasedKeyAlgorithms,
					Literal: "HostKeyAlgorithms",
				},
				Value: "ecdsa-sha2-nistp256-cert-v01@openssh.com, ecdsa-sha2-nistp384-cert-v01@openssh.com",
			},
		},
		{
			input: "HostKeyAlias server1",
			want: &ast.HostKeyAlias{
				Token: token.Token{
					Type:    token.HostKeyAlias,
					Literal: "HostKeyAlias",
				},
				Value: "server1",
			},
		},
		{
			input: "IdentitiesOnly yes",
			want: &ast.IdentitiesOnly{
				Token: token.Token{
					Type:    token.IdentitiesOnly,
					Literal: "IdentitiesOnly",
				},
				Value: "yes",
			},
		},
		{
			input: "IdentityAgent ~/.dir/agent.sock",
			want: &ast.IdentityAgent{
				Token: token.Token{
					Type:    token.IdentityAgent,
					Literal: "IdentityAgent",
				},
				Value: "~/.dir/agent.sock",
			},
		},
		{
			input: "IdentityFile ~/.ssh/id_ecdsa",
			want: &ast.IdentityFile{
				Token: token.Token{
					Type:    token.IdentityFile,
					Literal: "IdentityFile",
				},
				Value: "~/.ssh/id_ecdsa",
			},
		},
		{
			input: "IPQoS af31",
			want: &ast.IPQoS{
				Token: token.Token{
					Type:    token.IPQoS,
					Literal: "IPQoS",
				},
				Value: "af31",
			},
		},
		{
			input: "KbdInteractiveAuthentication no",
			want: &ast.KbdInteractiveAuthentication{
				Token: token.Token{
					Type:    token.KbdInteractiveAuthentication,
					Literal: "KbdInteractiveAuthentication",
				},
				Value: "no",
			},
		},
		{
			input: "KbdInteractiveDevices pam, skey, bsdauth",
			want: &ast.KbdInteractiveDevices{
				Token: token.Token{
					Type:    token.KbdInteractiveDevices,
					Literal: "KbdInteractiveDevices",
				},
				Value: "pam, skey, bsdauth",
			},
		},
		{
			input: "LocalCommand rsync -e ssh %d/testfile %r@%n:testfile",
			want: &ast.LocalCommand{
				Token: token.Token{
					Type:    token.LocalCommand,
					Literal: "LocalCommand",
				},
				Value: "rsync -e ssh %d/testfile %r@%n:testfile",
			},
		},
		{
			input: "LogLevel DEBUG",
			want: &ast.LogLevelStatement{
				Token: token.Token{
					Type:    token.LogLevel,
					Literal: "LogLevel",
				},
				Value: "DEBUG",
			},
		},
		{
			input: "MACs hmac-sha2-256, hmac-sha2-512, hmac-sha1",
			want: &ast.Macs{
				Token: token.Token{
					Type:    token.Macs,
					Literal: "MACs",
				},
				Value: "hmac-sha2-256, hmac-sha2-512, hmac-sha1",
			},
		},
		{
			input: "NoHostAuthenticationForLocalhost yes",
			want: &ast.NoHostAuthentication{
				Token: token.Token{
					Type:    token.NoHostAuthenticationForLocalhost,
					Literal: "NoHostAuthenticationForLocalhost",
				},
				Value: "yes",
			},
		},
		{
			input: "NumberOfPasswordPrompts 1",
			want: &ast.NumberOfPasswordPrompts{
				Token: token.Token{
					Type:    token.NumberOfPasswordPrompts,
					Literal: "NumberOfPasswordPrompts",
				},
				Value: "1",
			},
		},
		{
			input: "PasswordAuthentication no",
			want: &ast.PasswordAuthentication{
				Token: token.Token{
					Type:    token.PasswordAuthentication,
					Literal: "PasswordAuthentication",
				},
				Value: "no",
			},
		},
		{
			input: "PermitLocalCommand yes",
			want: &ast.PermitLocalCommand{
				Token: token.Token{
					Type:    token.PermitLocalCommand,
					Literal: "PermitLocalCommand",
				},
				Value: "yes",
			},
		},
		{
			input: "PKCS11Provider /usr/lib/i386-linux-gnu/opensc-pkcs11.so",
			want: &ast.PCKS11Provider{
				Token: token.Token{
					Type:    token.Pkcs11Provider,
					Literal: "PKCS11Provider",
				},
				Value: "/usr/lib/i386-linux-gnu/opensc-pkcs11.so",
			},
		},
		{
			input: "PreferredAuthentications password, keyboard-interactive",
			want: &ast.PreferredAuthentications{
				Token: token.Token{
					Type:    token.PreferredAuthentications,
					Literal: "PreferredAuthentications",
				},
				Value: "password, keyboard-interactive",
			},
		},
		{
			input: "ProxyCommand ssh -l jerry %h nc server2.nixcraft.com 22",
			want: &ast.ProxyCommand{
				Token: token.Token{
					Type:    token.ProxyCommand,
					Literal: "ProxyCommand",
				},
				Value: "ssh -l jerry %h nc server2.nixcraft.com 22",
			},
		},
		{
			input: "ProxyJump bastion-host-nickname",
			want: &ast.ProxyJump{
				Token: token.Token{
					Type:    token.ProxyJump,
					Literal: "ProxyJump",
				},
				Value: "bastion-host-nickname",
			},
		},
		{
			input: "ProxyUseFdpass yes",
			want: &ast.ProxyUserFDPass{
				Token: token.Token{
					Type:    token.ProxyUseFdpass,
					Literal: "ProxyUseFdpass",
				},
				Value: "yes",
			},
		},
		{
			input: "PubkeyAcceptedKeyTypes +ssh-dss",
			want: &ast.PubkeyAcceptedKeyTypes{
				Token: token.Token{
					Type:    token.PubkeyAcceptedKeyTypes,
					Literal: "PubkeyAcceptedKeyTypes",
				},
				Value: "+ssh-dss",
			},
		},
		{
			input: "PubkeyAuthentication yes",
			want: &ast.PubkeyAuthentication{
				Token: token.Token{
					Type:    token.PubkeyAuthentication,
					Literal: "PubkeyAuthentication",
				},
				Value: "yes",
			},
		},
		{
			input: "RekeyLimit 1G",
			want: &ast.RekeyLimit{
				Token: token.Token{
					Type:    token.RekeyLimit,
					Literal: "RekeyLimit",
				},
				Value: "1G",
			},
		},
		{
			input: "RemoteCommand cd /tmp && bash",
			want: &ast.RemoteCommand{
				Token: token.Token{
					Type:    token.RemoteCommand,
					Literal: "RemoteCommand",
				},
				Value: "cd /tmp && bash",
			},
		},
		{
			input: "RemoteForward 55555 localhost:22",
			want: &ast.RemoteForward{
				Token: token.Token{
					Type:    token.RemoteForward,
					Literal: "RemoteForward",
				},
				Value: "55555 localhost:22",
			},
		},
		{
			input: "RequestTTY force",
			want: &ast.RequestTTY{
				Token: token.Token{
					Type:    token.RequestTty,
					Literal: "RequestTTY",
				},
				Value: "force",
			},
		},
		{
			input: "SendEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES",
			want: &ast.SendEnv{
				Token: token.Token{
					Type:    token.SendEnv,
					Literal: "SendEnv",
				},
				Value: "LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES",
			},
		},
		{
			input: "ServerAliveInterval 10",
			want: &ast.ServerAliveOption{
				Token: token.Token{
					Type:    token.ServerAliveInterval,
					Literal: "ServerAliveInterval",
				},
				Value: "10",
			},
		},
		{
			input: "ServerAliveCountMax 3",
			want: &ast.ServerAliveOption{
				Token: token.Token{
					Type:    token.ServerAliveCountMax,
					Literal: "ServerAliveCountMax",
				},
				Value: "3",
			},
		},
		{
			input: "SetEnv FOO=bar",
			want: &ast.SetEnv{
				Token: token.Token{
					Type:    token.SetEnv,
					Literal: "SetEnv",
				},
				Value: "FOO=bar",
			},
		},
		{
			input: "StreamLocalBindMask 0177",
			want: &ast.StreamLocalBindMask{
				Token: token.Token{
					Type:    token.StreamLocalBindMask,
					Literal: "StreamLocalBindMask",
				},
				Value: "0177",
			},
		},
		{
			input: "StreamLocalBindUnlink yes",
			want: &ast.StreamLocalBindUnlink{
				Token: token.Token{
					Type:    token.StreamLocalBindUnlink,
					Literal: "StreamLocalBindUnlink",
				},
				Value: "yes",
			},
		},
		{
			input: "StrictHostKeyChecking chacha20-poly1305@openssh.com, aes128-ctr, aes192-ctr, aes256-ctr",
			want: &ast.StrictHostKeyChecking{
				Token: token.Token{
					Type:    token.StrictHostKeyChecking,
					Literal: "StrictHostKeyChecking",
				},
				Value: "chacha20-poly1305@openssh.com, aes128-ctr, aes192-ctr, aes256-ctr",
			},
		},
		{
			input: "TCPKeepAlive no",
			want: &ast.TCPKeepAlive{
				Token: token.Token{
					Type:    token.TCPKeepAlive,
					Literal: "TCPKeepAlive",
				},
				Value: "no",
			},
		},
		{
			input: "Tunnel point-to-point",
			want: &ast.Tunnel{
				Token: token.Token{
					Type:    token.Tunnel,
					Literal: "Tunnel",
				},
				Value: "point-to-point",
			},
		},
		{
			input: "TunnelDevice any",
			want: &ast.TunnelDevice{
				Token: token.Token{
					Type:    token.TunnelDevice,
					Literal: "TunnelDevice",
				},
				Value: "any",
			},
		},
		{
			input: "UpdateHostKeys ask",
			want: &ast.UpdateHostKeys{
				Token: token.Token{
					Type:    token.UpdateHostKeys,
					Literal: "UpdateHostKeys",
				},
				Value: "ask",
			},
		},
		{
			input: "UserKnownHostsFile ~/.ssh/known_hosts, ~/.ssh/known_hosts2",
			want: &ast.UserKnownHostsFile{
				Token: token.Token{
					Type:    token.UserKnownHostsFile,
					Literal: "UserKnownHostsFile",
				},
				Value: "~/.ssh/known_hosts, ~/.ssh/known_hosts2",
			},
		},
		{
			input: "VerifyHostKeyDNS yes",
			want: &ast.VerifyHostKeyDNS{
				Token: token.Token{
					Type:    token.VerifyHostKeyDNS,
					Literal: "VerifyHostKeyDNS",
				},
				Value: "yes",
			},
		},
		{
			input: "VisualHostKey yes",
			want: &ast.VisualHostKey{
				Token: token.Token{
					Type:    token.VisualHostKey,
					Literal: "VisualHostKey",
				},
				Value: "yes",
			},
		},
		{
			input: "XAuthLocation /usr/X11R6/bin/xauth",
			want: &ast.XAuthLocation{
				Token: token.Token{
					Type:    token.XauthLocation,
					Literal: "XAuthLocation",
				},
				Value: "/usr/X11R6/bin/xauth",
			},
		},
		{
			input: "ControlPath ~/.ssh/control-%h-%p-%r",
			want: &ast.ControlPath{
				Token: token.Token{
					Type:    token.ControlPath,
					Literal: "ControlPath",
				},
				Value: "~/.ssh/control-%h-%p-%r",
			},
		},
		{
			input: "Compression no",
			want: &ast.Compression{
				Token: token.Token{
					Type:    token.Compression,
					Literal: "Compression",
				},
				Value: "no",
			},
		},
		{
			input: "ForwardX11 yes",
			want: &ast.ForwardX11{
				Token: token.Token{
					Type:    token.ForwardX11,
					Literal: "ForwardX11",
				},
				Value: "yes",
			},
		},
		{
			input: "ConnectionTimeout 0",
			want: &ast.ConnectionTimeout{
				Token: token.Token{
					Type:    token.ConnectionTimeout,
					Literal: "ConnectionTimeout",
				},
				Value: "0",
			},
		},
		{
			input: "ConnectionAttempts 1",
			want: &ast.ConnectionAttempts{
				Token: token.Token{
					Type:    token.ConnectionAttempts,
					Literal: "ConnectionAttempts",
				},
				Value: "1",
			},
		},
		{
			input: "CheckHostIP no",
			want: &ast.CheckHostIP{
				Token: token.Token{
					Type:    token.CheckHostIP,
					Literal: "CheckHostIP",
				},
				Value: "no",
			},
		},
		{
			input: "Ciphers aes128-ctr,aes192-ctr,aes256-ctr",
			want: &ast.Ciphers{
				Token: token.Token{
					Type:    token.Ciphers,
					Literal: "Ciphers",
				},
				Value: "aes128-ctr, aes192-ctr, aes256-ctr",
			},
		},
		{
			input: "ClearAllForwardings yes",
			want: &ast.ClearAllForwardings{
				Token: token.Token{
					Type:    token.ClearAllForwardings,
					Literal: "ClearAllForwardings",
				},
				Value: "yes",
			},
		},
		{
			input: "ChallengeResponseAuthentication no",
			want: &ast.ChallengeAuthentication{
				Token: token.Token{
					Type:    token.ChallengeResponseAuthentication,
					Literal: "ChallengeResponseAuthentication",
				},
				Value: "no",
			},
		},
		{
			input: "CanonicalizeFallbackLocal yes",
			want: &ast.CanonicalizeFallbackLocal{
				Token: token.Token{
					Type:    token.CanonicalizeFallbackLocal,
					Literal: "CanonicalizeFallbackLocal",
				},
				Value: "yes",
			},
		},
		{
			input: "CanonicalizeHostname yes",
			want: &ast.CanonicalizeHostname{
				Token: token.Token{
					Type:    token.CanonicalizeHostname,
					Literal: "CanonicalizeHostname",
				},
				Value: "yes",
			},
		},
		{
			input: "CanonicalizeMaxDots 0",
			want: &ast.CanonicalizeMaxDots{
				Token: token.Token{
					Type:    token.CanonicalizeMaxDots,
					Literal: "CanonicalizeMaxDots",
				},
				Value: "0",
			},
		},
		{
			input: "CanonicalizePermittedCNAMEs mail.*.example.com:anycast-mail.int.example.com dns*.example.com:dns*.dmz.example.com",
			want: &ast.CanonicalizePermittedCNames{
				Token: token.Token{
					Type:    token.CanonicalizePermittedCnames,
					Literal: "CanonicalizePermittedCNAMEs",
				},
				Value: "mail.*.example.com:anycast-mail.int.example.com dns*.example.com:dns*.dmz.example.com",
			},
		},
		{
			input: "CASignatureAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521",
			want: &ast.CASignatureAlgorithms{
				Token: token.Token{
					Type:    token.CaSignatureAlgorithms,
					Literal: "CASignatureAlgorithms",
				},
				Value: "ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521",
			},
		},
		{
			input: "CertificateFile ~/.ssh/id_ecdsa",
			want: &ast.CertificateFile{
				Token: token.Token{
					Type:    token.CertificateFile,
					Literal: "CertificateFile",
				},
				Value: "~/.ssh/id_ecdsa",
			},
		},
		{
			input: "Include ~/.ssh/pi_config",
			want: &ast.Include{
				Token: token.Token{
					Type:    token.Include,
					Literal: "Include",
				},
				Value: "~/.ssh/pi_config",
			},
		},
		{
			input: "Match all",
			want: &ast.Match{
				Token: token.Token{
					Type:    token.Match,
					Literal: "Match",
				},
				Value: "all",
			},
		},
		{
			input: "Match canonical all",
			want: &ast.Match{
				Token: token.Token{
					Type:    token.Match,
					Literal: "Match",
				},
				Value: "canonical all",
			},
		},
		{
			input: "Match final all",
			want: &ast.Match{
				Token: token.Token{
					Type:    token.Match,
					Literal: "Match",
				},
				Value: "final all",
			},
		},
		{
			input: "Match user bob, joe, phil",
			want: &ast.Match{
				Token: token.Token{
					Type:    token.Match,
					Literal: "Match",
				},
				Value: "user bob, joe, phil",
			},
		},
		{
			input: "Match host \"specified-domain.com\" user \"specified-user\"",
			want: &ast.Match{
				Token: token.Token{
					Type:    token.Match,
					Literal: "Match",
				},
				Value: "host \"specified-domain.com\" user \"specified-user\"",
			},
		},
		{
			input: "Match exec \"onsubnet --not 10.10.1.\" host my-server",
			want: &ast.Match{
				Token: token.Token{
					Type:    token.Match,
					Literal: "Match",
				},
				Value: "exec \"onsubnet --not 10.10.1.\" host my-server",
			},
		},
	}

	for _, tt := range tests {
		l := lexer.New(tt.input)
		p := New(l)

		t.Run(tt.input, func(t *testing.T) {
			if got := p.parseStatement(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseStatement() = %v, want %v", got, tt.want)
			}
		})
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
