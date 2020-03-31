package parser

import (
	"reflect"
	"testing"

	"github.com/calvernaz/scp/ast"
	"github.com/calvernaz/scp/lexer"
	"github.com/calvernaz/scp/token"
)

func TestParser_parseStatement(t *testing.T) {

	tests := []struct {
		input string
		want  ast.Statement
	}{
		{
			input: "HostName host1.example.com",
			want: &ast.HostName{
				Token: token.Token{
					Type:    token.HOSTNAME,
					Literal: "HostName",
				},
				Value: "host1.example.com",
			},
		},
		{
			input: "IdentityFile ~/.ssh/key_name_for_github",
			want: &ast.IdentityFile{
				Token: token.Token{
					Type:    token.IDENTITY_FILE,
					Literal: "IdentityFile",
				},
				Value: "~/.ssh/key_name_for_github",
			},
		},
		{
			input: "User user1",
			want: &ast.User{
				Token: token.Token{
					Type:    token.USER,
					Literal: "User",
				},
				Value: "user1",
			},
		},
		{
			input: "Port 22",
			want: &ast.Port{
				Token: token.Token{
					Type:    token.PORT,
					Literal: "Port",
				},
				Value: "22",
			},
		},
		{
			input: "UseKeyChain yes",
			want: &ast.UseKeyChain{
				Token: token.Token{
					Type:    token.USE_KEY_CHAIN,
					Literal: "UseKeyChain",
				},
				Value: "yes",
			},
		},
		{
			input: "AddKeysToAgent yes",
			want: &ast.AddKeysToAgent{
				Token: token.Token{
					Type:    token.ADD_KEYS_TO_AGENT,
					Literal: "AddKeysToAgent",
				},
				Value: "yes",
			},
		},
		{
			input: "LocalForward 8443 127.0.0.1:443",
			want: &ast.LocalForward{
				Token: token.Token{
					Type:    token.LOCAL_FORWARD,
					Literal: "LocalForward",
				},
				Value: "8443 127.0.0.1:443",
			},
		},
		{
			input: "ControlMaster yes",
			want: &ast.ControlMaster{
				Token: token.Token{
					Type:    token.CONTROL_MASTER,
					Literal: "ControlMaster",
				},
				Value: "yes",
			},
		},
		{
			input: "ControlPersist no",
			want: &ast.ControlPersist{
				Token: token.Token{
					Type:    token.CONTROL_PERSIST,
					Literal: "ControlPersist",
				},
				Value: "no",
			},
		},
		{
			input: "DynamicForward localhost:3333",
			want: &ast.DynamicForward{
				Token: token.Token{
					Type:    token.DYNAMIC_FORWARD,
					Literal: "DynamicForward",
				},
				Value: "localhost:3333",
			},
		},
		{
			input: "EscapeChar ~",
			want: &ast.EscapeChar{
				Token: token.Token{
					Type:    token.ESCAPE_CHAR,
					Literal: "EscapeChar",
				},
				Value: "~",
			},
		},
		{
			input: "ExitOnForwardFailure yes",
			want: &ast.ExitOnForwardFailure{
				Token: token.Token{
					Type:    token.EXIT_ON_FORWARD_FAILURE,
					Literal: "ExitOnForwardFailure",
				},
				Value: "yes",
			},
		},
		{
			input: "FingerprintHash sha256",
			want: &ast.FingerprintHash{
				Token: token.Token{
					Type:    token.FINGERPRINT_HASH,
					Literal: "FingerprintHash",
				},
				Value: "sha256",
			},
		},
		{
			input: "ForwardAgent yes",
			want: &ast.ForwardAgent{
				Token: token.Token{
					Type:    token.FORWARD_AGENT,
					Literal: "ForwardAgent",
				},
				Value: "yes",
			},
		},
		{
			input: "ForwardX11Timeout 0",
			want: &ast.ForwardX11Timeout{
				Token: token.Token{
					Type:    token.FORWARD_X11_TIMEOUT,
					Literal: "ForwardX11Timeout",
				},
				Value: "0",
			},
		},
		{
			input: "ForwardX11Trusted yes",
			want: &ast.ForwardX11Trusted{
				Token: token.Token{
					Type:    token.FORWARD_X11_TRUSTED,
					Literal: "ForwardX11Trusted",
				},
				Value: "yes",
			},
		},
		{
			input: "GatewayPorts yes",
			want: &ast.GatewayPorts{
				Token: token.Token{
					Type:    token.GATEWAY_PORTS,
					Literal: "GatewayPorts",
				},
				Value: "yes",
			},
		},
		{
			input: "GlobalKnownHostsFile /etc/ssh/ssh_known_hosts, /etc/ssh/ssh_known_hosts2, /etc/ssh/ssh_known_hosts3",
			want: &ast.GlobalKnownHostsFile{
				Token: token.Token{
					Type:    token.GLOBAL_KNOWN_HOSTS_FILE,
					Literal: "GlobalKnownHostsFile",
				},
				Value: "/etc/ssh/ssh_known_hosts, /etc/ssh/ssh_known_hosts2, /etc/ssh/ssh_known_hosts3",
			},
		},
		{
			input: "GSSAPIAuthentication yes",
			want: &ast.GSSApiAuthentication{
				Token: token.Token{
					Type:    token.GSSAPI_AUTHENTICATION,
					Literal: "GSSAPIAuthentication",
				},
				Value: "yes",
			},
		},
		{
			input: "GSSAPIDeleteCredentials yes",
			want: &ast.GSSApiDelegateCredentials{
				Token: token.Token{
					Type:    token.GSSAPI_DELEGATE_CREDENTIALS,
					Literal: "GSSAPIDeleteCredentials",
				},
				Value: "yes",
			},
		},
		{
			input: "HashKnownHosts yes",
			want: &ast.HashKnownHosts{
				Token: token.Token{
					Type:    token.HASH_KNOWN_HOSTS,
					Literal: "HashKnownHosts",
				},
				Value: "yes",
			},
		},
		{
			input: "HostbasedAuthentication yes",
			want: &ast.HostBasedAuthentication{
				Token: token.Token{
					Type:    token.HOSTBASED_AUTHENTICATION,
					Literal: "HostbasedAuthentication",
				},
				Value: "yes",
			},
		},
		{
			input:"HostbasedKeyTypes ecdsa-sha2-nistp256-cert-v01@openssh.com, ecdsa-sha2-nistp384-cert-v01@openssh.com",
			want: &ast.HostBasedKeyTypes{
				Token: token.Token{
					Type:    token.HOSTBASED_KEY_TYPES,
					Literal: "HostbasedKeyTypes",
				},
				Value: "ecdsa-sha2-nistp256-cert-v01@openssh.com, ecdsa-sha2-nistp384-cert-v01@openssh.com",
			},
		},
		{
			input: "HostKeyAlgorithms ecdsa-sha2-nistp256-cert-v01@openssh.com, ecdsa-sha2-nistp384-cert-v01@openssh.com",
			want: &ast.HostKeyAlgorithms{
				Token: token.Token{
					Type:    token.HOSTBASED_KEY_ALGORITHMS,
					Literal: "HostKeyAlgorithms",
				},
				Value: "ecdsa-sha2-nistp256-cert-v01@openssh.com, ecdsa-sha2-nistp384-cert-v01@openssh.com",
			},
		},
		{
			input: "HostKeyAlias server1",
			want: &ast.HostKeyAlias{
				Token: token.Token{
					Type:    token.HOST_KEY_ALIAS,
					Literal: "HostKeyAlias",
				},
				Value: "server1",
			},
		},
		{
			input: "IdentitiesOnly yes",
			want: &ast.IdentitiesOnly{
				Token: token.Token{
					Type:    token.IDENTITIES_ONLY,
					Literal: "IdentitiesOnly",
				},
				Value: "yes",
			},
		},
		{
			input: "IdentityAgent ~/.dir/agent.sock",
			want: &ast.IdentityAgent{
				Token: token.Token{
					Type:    token.IDENTITY_AGENT,
					Literal: "IdentityAgent",
				},
				Value: "~/.dir/agent.sock",
			},
		},
		{
			input: "IdentityFile ~/.ssh/id_ecdsa",
			want: &ast.IdentityFile{
				Token: token.Token{
					Type:    token.IDENTITY_FILE,
					Literal: "IdentityFile",
				},
				Value: "~/.ssh/id_ecdsa",
			},
		},
		{
			input: "IPQoS af31",
			want: &ast.IPQoS{
				Token: token.Token{
					Type:    token.IP_QOS,
					Literal: "IPQoS",
				},
				Value: "af31",
			},
		},
		{
			input: "KbdInteractiveAuthentication no",
			want: &ast.KbdInteractiveAuthentication{
				Token: token.Token{
					Type:    token.KBD_INTERACTIVE_AUTHENTICATION,
					Literal: "KbdInteractiveAuthentication",
				},
				Value: "no",
			},
		},
		{
			input: "KbdInteractiveDevices pam, skey, bsdauth",
			want: &ast.KbdInteractiveDevices{
				Token: token.Token{
					Type:    token.KBD_INTERACTIVE_DEVICES,
					Literal: "KbdInteractiveDevices",
				},
				Value: "pam, skey, bsdauth",
			},
		},
		{
			input: "LocalCommand rsync -e ssh %d/testfile %r@%n:testfile",
			want: &ast.LocalCommand{
				Token: token.Token{
					Type:    token.LOCAL_COMMAND,
					Literal: "LocalCommand",
				},
				Value: "rsync -e ssh %d/testfile %r@%n:testfile",
			},
		},
		{
			input: "LogLevel DEBUG",
			want: &ast.LogLevelStatement{
				Token: token.Token{
					Type:    token.LOG_LEVEL,
					Literal: "LogLevel",
				},
				Value: "DEBUG",
			},
		},
		{
			input: "MACs hmac-sha2-256, hmac-sha2-512, hmac-sha1",
			want: &ast.Macs{
				Token: token.Token{
					Type:    token.MACS,
					Literal: "MACs",
				},
				Value: "hmac-sha2-256, hmac-sha2-512, hmac-sha1",
			},
		},
		{
			input: "NoHostAuthenticationForLocalhost yes",
			want: &ast.NoHostAuthentication{
				Token: token.Token{
					Type:    token.NO_HOST_AUTHENTICATION_FOR_LOCALHOST,
					Literal: "NoHostAuthenticationForLocalhost",
				},
				Value: "yes",
			},
		},
		{
			input: "NumberOfPasswordPrompts 1",
			want: &ast.NumberOfPasswordPrompts{
				Token: token.Token{
					Type:    token.NUMBER_OF_PASSWORD_PROMPTS,
					Literal: "NumberOfPasswordPrompts",
				},
				Value: "1",
			},
		},
		{
			input: "PasswordAuthentication no",
			want: &ast.PasswordAuthentication{
				Token: token.Token{
					Type:    token.PASSWORD_AUTHENTICATION,
					Literal: "PasswordAuthentication",
				},
				Value: "no",
			},
		},
		{
			input: "PermitLocalCommand yes",
			want: &ast.PermitLocalCommand{
				Token: token.Token{
					Type:    token.PERMIT_LOCAL_COMMAND,
					Literal: "PermitLocalCommand",
				},
				Value: "yes",
			},
		},
		{
			input: "PKCS11Provider /usr/lib/i386-linux-gnu/opensc-pkcs11.so",
			want: &ast.PCKS11Provider{
				Token: token.Token{
					Type:    token.PKCS11_PROVIDER,
					Literal: "PKCS11Provider",
				},
				Value: "/usr/lib/i386-linux-gnu/opensc-pkcs11.so",
			},
		},
		{
			input: "PreferredAuthentications password, keyboard-interactive",
			want: &ast.PreferredAuthentications{
				Token: token.Token{
					Type:    token.PREFERRED_AUTHENTICATIONS,
					Literal: "PreferredAuthentications",
				},
				Value: "password, keyboard-interactive",
			},
		},
		{
			input: "ProxyCommand ssh -l jerry %h nc server2.nixcraft.com 22",
			want: &ast.ProxyCommandStatement{
				Token: token.Token{
					Type:    token.PROXY_COMMAND,
					Literal: "ProxyCommand",
				},
				Value: "ssh -l jerry %h nc server2.nixcraft.com 22",
			},
		},
		{
			input: "ProxyJump bastion-host-nickname",
			want: &ast.ProxyJump{
				Token: token.Token{
					Type:    token.PROXY_JUMP,
					Literal: "ProxyJump",
				},
				Value: "bastion-host-nickname",
			},
		},
		{
			input: "ProxyUseFdpass yes",
			want: &ast.ProxyUserFDPass{
				Token: token.Token{
					Type:    token.PROXY_USE_FDPASS,
					Literal: "ProxyUseFdpass",
				},
				Value: "yes",
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
