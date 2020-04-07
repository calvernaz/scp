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
			input: "HostbasedKeyTypes ecdsa-sha2-nistp256-cert-v01@openssh.com, ecdsa-sha2-nistp384-cert-v01@openssh.com",
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
		{
			input: "PubkeyAcceptedKeyTypes +ssh-dss",
			want: &ast.PubkeyAcceptedKeyTypes{
				Token: token.Token{
					Type:    token.PUBKEY_ACCEPTED_KEY_TYPES,
					Literal: "PubkeyAcceptedKeyTypes",
				},
				Value: "+ssh-dss",
			},
		},
		{
			input: "PubkeyAuthentication yes",
			want: &ast.PubkeyAuthentication{
				Token: token.Token{
					Type:    token.PUBKEY_AUTHENTICATION,
					Literal: "PubkeyAuthentication",
				},
				Value: "yes",
			},
		},
		{
			input: "RekeyLimit 1G",
			want: &ast.RekeyLimit{
				Token: token.Token{
					Type:    token.REKEY_LIMIT,
					Literal: "RekeyLimit",
				},
				Value: "1G",
			},
		},
		{
			input: "RemoteCommand cd /tmp && bash",
			want: &ast.RemoteCommand{
				Token: token.Token{
					Type:    token.REMOTE_COMMAND,
					Literal: "RemoteCommand",
				},
				Value: "cd /tmp && bash",
			},
		},
		{
			input: "RemoteForward 55555 localhost:22",
			want: &ast.RemoteForward{
				Token: token.Token{
					Type:    token.REMOTE_FORWARD,
					Literal: "RemoteForward",
				},
				Value: "55555 localhost:22",
			},
		},
		{
			input: "RequestTTY force",
			want: &ast.RequestTTY{
				Token: token.Token{
					Type:    token.REQUEST_TTY,
					Literal: "RequestTTY",
				},
				Value: "force",
			},
		},
		{
			input: "SendEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES",
			want: &ast.SendEnv{
				Token: token.Token{
					Type:    token.SEND_ENV,
					Literal: "SendEnv",
				},
				Value: "LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES",
			},
		},
		{
			input: "ServerAliveInterval 10",
			want: &ast.ServerAliveOption{
				Token: token.Token{
					Type:    token.SERVER_ALIVE_INTERVAL,
					Literal: "ServerAliveInterval",
				},
				Value: "10",
			},
		},
		{
			input: "ServerAliveCountMax 3",
			want: &ast.ServerAliveOption{
				Token: token.Token{
					Type:    token.SERVER_ALIVE_COUNT_MAX,
					Literal: "ServerAliveCountMax",
				},
				Value: "3",
			},
		},
		{
			input: "SetEnv FOO=bar",
			want: &ast.SetEnv{
				Token: token.Token{
					Type:    token.SET_ENV,
					Literal: "SetEnv",
				},
				Value: "FOO=bar",
			},
		},
		{
			input: "StreamLocalBindMask 0177",
			want: &ast.StreamLocalBindMask{
				Token: token.Token{
					Type:    token.STREAM_LOCAL_BIND_MASK,
					Literal: "StreamLocalBindMask",
				},
				Value: "0177",
			},
		},
		{
			input: "StreamLocalBindUnlink yes",
			want: &ast.StreamLocalBindUnlink{
				Token: token.Token{
					Type:    token.STREAM_LOCAL_BIND_UNLINK,
					Literal: "StreamLocalBindUnlink",
				},
				Value: "yes",
			},
		},
		{
			input: "StrictHostKeyChecking chacha20-poly1305@openssh.com, aes128-ctr, aes192-ctr, aes256-ctr",
			want: &ast.StrictHostKeyChecking{
				Token: token.Token{
					Type:    token.STRICT_HOST_KEY_CHECKING,
					Literal: "StrictHostKeyChecking",
				},
				Value: "chacha20-poly1305@openssh.com, aes128-ctr, aes192-ctr, aes256-ctr",
			},
		},
		{
			input: "TCPKeepAlive no",
			want: &ast.TcpKeepAlive{
				Token: token.Token{
					Type:    token.TCP_KEEP_ALIVE,
					Literal: "TCPKeepAlive",
				},
				Value: "no",
			},
		},
		{
			input: "Tunnel point-to-point",
			want: &ast.Tunnel{
				Token: token.Token{
					Type:    token.TUNNEL,
					Literal: "Tunnel",
				},
				Value: "point-to-point",
			},
		},
		{
			input: "TunnelDevice any",
			want: &ast.TunnelDevice{
				Token: token.Token{
					Type:    token.TUNNEL_DEVICE,
					Literal: "TunnelDevice",
				},
				Value: "any",
			},
		},
		{
			input: "UpdateHostKeys ask",
			want: &ast.UpdateHostKeys{
				Token: token.Token{
					Type:    token.UPDATE_HOST_KEYS,
					Literal: "UpdateHostKeys",
				},
				Value: "ask",
			},
		},
		{
			input: "UserKnownHostsFile ~/.ssh/known_hosts, ~/.ssh/known_hosts2",
			want: &ast.UserKnownHostsFile{
				Token: token.Token{
					Type:    token.USER_KNOWN_HOSTS_FILE,
					Literal: "UserKnownHostsFile",
				},
				Value: "~/.ssh/known_hosts, ~/.ssh/known_hosts2",
			},
		},
		{
			input: "VerifyHostKeyDNS yes",
			want: &ast.VerifyHostKeyDNS{
				Token: token.Token{
					Type:    token.VERIFY_HOST_KEY_DNS,
					Literal: "VerifyHostKeyDNS",
				},
				Value: "yes",
			},
		},
		{
			input: "VisualHostKey yes",
			want: &ast.VisualHostKey{
				Token: token.Token{
					Type:    token.VISUAL_HOST_KEY,
					Literal: "VisualHostKey",
				},
				Value: "yes",
			},
		},
		{
			input: "XAuthLocation /usr/X11R6/bin/xauth",
			want: &ast.XAuthLocation{
				Token: token.Token{
					Type:    token.XAUTH_LOCATION,
					Literal: "XAuthLocation",
				},
				Value: "/usr/X11R6/bin/xauth",
			},
		},
		{
			input: "ControlPath ~/.ssh/control-%h-%p-%r",
			want: &ast.ControlPath{
				Token: token.Token{
					Type:    token.CONTROL_PATH,
					Literal: "ControlPath",
				},
				Value: "~/.ssh/control-%h-%p-%r",
			},
		},
		{
			input: "Compression no",
			want: &ast.CompressionStatement{
				Token: token.Token{
					Type:    token.COMPRESSION,
					Literal: "Compression",
				},
				Value: "no",
			},
		},
		{
			input: "ForwardX11 yes",
			want: &ast.ForwardX11{
				Token: token.Token{
					Type:    token.FORWARD_X11,
					Literal: "ForwardX11",
				},
				Value: "yes",
			},
		},
		{
			input: "ConnectionTimeout 0",
			want: &ast.ConnectionTimeout{
				Token: token.Token{
					Type:    token.CONNECTION_TIMEOUT,
					Literal: "ConnectionTimeout",
				},
				Value: "0",
			},
		},
		{
			input: "ConnectionAttempts 1",
			want: &ast.ConnectionAttempts{
				Token: token.Token{
					Type:    token.CONNECTION_ATTEMPTS,
					Literal: "ConnectionAttempts",
				},
				Value: "1",
			},
		},
		{
			input: "CheckHostIP no",
			want: &ast.CheckHostIP{
				Token: token.Token{
					Type:    token.CHECK_HOST_IP,
					Literal: "CheckHostIP",
				},
				Value: "no",
			},
		},
		{
			input: "Ciphers aes128-ctr,aes192-ctr,aes256-ctr",
			want: &ast.Ciphers{
				Token: token.Token{
					Type:    token.CIPHERS,
					Literal: "Ciphers",
				},
				Value: "aes128-ctr, aes192-ctr, aes256-ctr",
			},
		},
		{
			input: "ClearAllForwardings yes",
			want: &ast.ClearAllForwardings{
				Token: token.Token{
					Type:    token.CLEAR_ALL_FORWARDINGS,
					Literal: "ClearAllForwardings",
				},
				Value: "yes",
			},
		},
		{
			input: "ChallengeResponseAuthentication no",
			want: &ast.ChallengeAuthentication{
				Token: token.Token{
					Type:    token.CHALLENGE_RESPONSE_AUTHENTICATION,
					Literal: "ChallengeResponseAuthentication",
				},
				Value: "no",
			},
		},
		{
			input: "CanonicalizeFallbackLocal yes",
			want: &ast.CanonicalizeFallbackLocal{
				Token: token.Token{
					Type:    token.CANONICALIZE_FALLBACK_LOCAL,
					Literal: "CanonicalizeFallbackLocal",
				},
				Value: "yes",
			},
		},
		{
			input: "CanonicalizeHostname yes",
			want: &ast.CanonicalizeHostname{
				Token: token.Token{
					Type:    token.CANONICALIZE_HOSTNAME,
					Literal: "CanonicalizeHostname",
				},
				Value: "yes",
			},
		},
		{
			input: "CanonicalizeMaxDots 0",
			want: &ast.CanonicalizeMaxDots{
				Token: token.Token{
					Type:    token.CANONICALIZE_MAX_DOTS,
					Literal: "CanonicalizeMaxDots",
				},
				Value: "0",
			},
		},
		{
			input: "CanonicalizePermittedCNAMEs mail.*.example.com:anycast-mail.int.example.com dns*.example.com:dns*.dmz.example.com",
			want: &ast.CanonicalizePermittedCNames{
				Token: token.Token{
					Type:    token.CANONICALIZE_PERMITTED_CNAMES,
					Literal: "CanonicalizePermittedCNAMEs",
				},
				Value: "mail.*.example.com:anycast-mail.int.example.com dns*.example.com:dns*.dmz.example.com",
			},
		},
		{
			input: "CASignatureAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521",
			want: &ast.CASignatureAlgorithms{
				Token: token.Token{
					Type:    token.CA_SIGNATURE_ALGORITHMS,
					Literal: "CASignatureAlgorithms",
				},
				Value: "ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521",
			},
		},
		{
			input: "CertificateFile ~/.ssh/id_ecdsa",
			want: &ast.CertificateFile{
				Token: token.Token{
					Type:    token.CERTIFICATE_FILE,
					Literal: "CertificateFile",
				},
				Value: "~/.ssh/id_ecdsa",
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
