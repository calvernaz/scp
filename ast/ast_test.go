package ast

import (
	"fmt"

	"github.com/calvernaz/scp/token"
)

func ExampleHostStatement_String() {

	host := HostStatement{
		Token: token.Token{
			Type:    token.Host,
			Literal: "Host",
		},
		Value: "host.com",
		Statement: &BlockStatement{
			Statements: []Statement{
				Compression{
					Token: token.Token{
						Type:    token.Compression,
						Literal: "Compression",
					},
					Value: "yes",
				},
			},
		},
	}

	fmt.Println(host.String())
	// Output:
	// Host host.com
	//  Compression yes
}

func ExampleHostName_String() {
	hostname := HostName{
		Token: token.Token{
			Type:    token.Hostname,
			Literal: "Hostname",
		},
		Value: "hostname.com",
	}
	fmt.Println(hostname)
	// Output:
	// Hostname hostname.com
}

func ExampleIdentityFile_String() {
	identityFile := IdentityFile{
		Token: token.Token{
			Type:    token.IdentityFile,
			Literal: "IdentityFile",
		},
		Value: "~/.ssh/config",
	}
	fmt.Println(identityFile)
	// Output:
	// IdentityFile ~/.ssh/config
}

func ExampleUser_String() {
	user := User{
		Token: token.Token{
			Type:    token.User,
			Literal: "User",
		},
		Value: "root",
	}
	fmt.Println(user)
	// Output:
	// User root
}

func ExamplePort_String() {
	port := Port{
		Token: token.Token{
			Type:    token.Port,
			Literal: "Port",
		},
		Value: "22",
	}
	fmt.Println(port)
	// Output:
	// Port 22
}

func ExampleUseKeyChain_String() {
	useKeyChain := UseKeyChain{
		Token: token.Token{
			Type:    token.UseKeyChain,
			Literal: "UseKeyChain",
		},
		Value: "yes",
	}
	fmt.Println(useKeyChain)
	// Output:
	// UseKeyChain yes
}

func ExampleAddKeysToAgent_String() {
	addKeysToAgent := AddKeysToAgent{
		Token: token.Token{
			Type:    token.AddKeysToAgent,
			Literal: "AddKeysToAgent",
		},
		Value: "yes",
	}
	// Output:
	// AddKeysToAgent yes
	fmt.Println(addKeysToAgent)
}

func ExampleLocalForward_String() {
	localForward := LocalForward{
		Token: token.Token{
			Type:    token.LocalForward,
			Literal: "LocalForward",
		},
		Value: "8443 127.0.0.1:443",
	}
	fmt.Println(localForward)
	// Output:
	// LocalForward 8443 127.0.0.1:443
}

func ExampleControlMaster_String() {
	controlMaster := ControlMaster{
		Token: token.Token{
			Type:    token.ControlMaster,
			Literal: "ControlMaster",
		},
		Value: "yes",
	}
	fmt.Println(controlMaster)
	// Output:
	// ControlMaster yes
}

func ExampleControlPersist_String() {
	controlPersist := ControlPersist{
		Token: token.Token{
			Type:    token.ControlPersist,
			Literal: "ControlPersist",
		},
		Value: "no",
	}
	fmt.Println(controlPersist)
	// Output:
	// ControlPersist no
}

func ExampleServerAliveOption_String() {
	serverAliveOption := ServerAliveOption{
		Token: token.Token{
			Type:    token.ServerAliveInterval,
			Literal: "ServerAliveInterval",
		},
		Value: "10",
	}
	fmt.Println(serverAliveOption)
	// Output:
	// ServerAliveInterval 10
}

func ExampleCompressionLevelStatement_String() {
	compressionLevel := CompressionLevel{
		Token: token.Token{
			Type:    token.CompressionLevel,
			Literal: "CompressionLevel",
		},
		Value: "1",
	}
	fmt.Println(compressionLevel)
	// Output:
	// CompressionLevel 1
}

func ExampleUserKnownHostsFile_String() {
	userKnownHostsFile := UserKnownHostsFile{
		Token: token.Token{
			Type:    token.UserKnownHostsFile,
			Literal: "UserKnownHostsFile",
		},
		Value: "~/.ssh/known_hosts, ~/.ssh/known_hosts2",
	}
	fmt.Println(userKnownHostsFile)
	// Output:
	// UserKnownHostsFile ~/.ssh/known_hosts, ~/.ssh/known_hosts2
}

func ExampleStrictHostKeyChecking_String() {
	strictHostKeyChecking := StrictHostKeyChecking{
		Token: token.Token{
			Type:    token.StrictHostKeyChecking,
			Literal: "StrictHostKeyChecking",
		},
		Value: "chacha20-poly1305@openssh.com, aes128-ctr, aes192-ctr, aes256-ctr",
	}
	fmt.Println(strictHostKeyChecking)
	// Output:
	// StrictHostKeyChecking chacha20-poly1305@openssh.com, aes128-ctr, aes192-ctr, aes256-ctr
}

func ExampleProxyCommand_String() {
	proxyCommand := ProxyCommand{
		Token: token.Token{
			Type:    token.ProxyCommand,
			Literal: "ProxyCommand",
		},
		Value: "ssh -l jerry %h nc server2.nixcraft.com 22",
	}
	fmt.Println(proxyCommand)
	// Output:
	// ProxyCommand ssh -l jerry %h nc server2.nixcraft.com 22
}

func ExampleForwardAgent_String() {
	forwardAgent := ForwardAgent{
		Token: token.Token{
			Type:    token.ForwardAgent,
			Literal: "ForwardAgent",
		},
		Value: "yes",
	}
	fmt.Println(forwardAgent)
	// Output:
	// ForwardAgent yes
}

func ExampleLogLevelStatement_String() {
	logLevelStatement := LogLevelStatement{
		Token: token.Token{
			Type:    token.LogLevel,
			Literal: "LogLevel",
		},
		Value: "DEBUG",
	}
	fmt.Println(logLevelStatement)
	// Output:
	// LogLevel DEBUG
}

func ExampleCanonicalizeFallbackLocal_String() {
	canonicalizeFallbackLocal := CanonicalizeFallbackLocal{
		Token: token.Token{
			Type:    token.CanonicalizeFallbackLocal,
			Literal: "CanonicalizeFallbackLocal",
		},
		Value: "yes",
	}
	fmt.Println(canonicalizeFallbackLocal)
	// Output:
	// CanonicalizeFallbackLocal yes
}

func ExampleCanonicalizeHostname_String() {
	canonicalizeHostname := CanonicalizeHostname{
		Token: token.Token{
			Type:    token.CanonicalizeHostname,
			Literal: "CanonicalizeHostname",
		},
		Value: "yes",
	}
	fmt.Println(canonicalizeHostname)
	// Output:
	// CanonicalizeHostname yes
}

func ExampleCanonicalizeMaxDots_String() {
	canonicalizeMaxDots := CanonicalizeMaxDots{
		Token: token.Token{
			Type:    token.CanonicalizeMaxDots,
			Literal: "CanonicalizeMaxDots",
		},
		Value: "0",
	}
	fmt.Println(canonicalizeMaxDots)
	// Output:
	// CanonicalizeMaxDots 0
}

func ExampleCanonicalizePermittedCNames_String() {
	canonicalizePermittedCNames := CanonicalizePermittedCNames{
		Token: token.Token{
			Type:    token.CanonicalizePermittedCnames,
			Literal: "CanonicalizePermittedCNAMEs",
		},
		Value: "mail.*.example.com:anycast-mail.int.example.com dns*.example.com:dns*.dmz.example.com",
	}
	fmt.Println(canonicalizePermittedCNames)
	// Output:
	// CanonicalizePermittedCNAMEs mail.*.example.com:anycast-mail.int.example.com dns*.example.com:dns*.dmz.example.com
}

func ExampleCASignatureAlgorithms_String() {
	caSignatureAlgorithms := CASignatureAlgorithms{
		Token: token.Token{
			Type:    token.CaSignatureAlgorithms,
			Literal: "CASignatureAlgorithms",
		},
		Value: "ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521",
	}
	fmt.Println(caSignatureAlgorithms)
	// Output:
	// CASignatureAlgorithms ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521
}

func ExampleCertificateFile_String() {
	certificateFile := CertificateFile{
		Token: token.Token{
			Type:    token.CertificateFile,
			Literal: "CertificateFile",
		},
		Value: "~/.ssh/id_ecdsa",
	}
	fmt.Println(certificateFile)
	// Output:
	// CertificateFile ~/.ssh/id_ecdsa
}

func ExampleChallengeAuthentication_String() {
	challengeAuthentication := ChallengeAuthentication{
		Token: token.Token{
			Type:    token.ChallengeResponseAuthentication,
			Literal: "ChallengeResponseAuthentication",
		},
		Value: "no",
	}
	fmt.Println(challengeAuthentication)
	// Output:
	// ChallengeResponseAuthentication no
}

func ExampleCheckHostIP_String() {
	checkHostIP := CheckHostIP{
		Token: token.Token{
			Type:    token.CheckHostIP,
			Literal: "CheckHostIP",
		},
		Value: "no",
	}
	fmt.Println(checkHostIP)
	// Output:
	// CheckHostIP no
}

func ExampleCiphers_String() {
	ciphers := Ciphers{
		Token: token.Token{
			Type:    token.Ciphers,
			Literal: "Ciphers",
		},
		Value: "aes128-ctr, aes192-ctr, aes256-ctr",
	}
	fmt.Println(ciphers)
	// Output:
	// Ciphers aes128-ctr, aes192-ctr, aes256-ctr
}

func ExampleClearAllForwardings_String() {
	clearAllForwardings := ClearAllForwardings{
		Token: token.Token{
			Type:    token.ClearAllForwardings,
			Literal: "ClearAllForwardings",
		},
		Value: "yes",
	}
	fmt.Println(clearAllForwardings)
	// Output:
	// ClearAllForwardings yes
}

func ExampleConnectionAttempts_String() {
	connectionAttempts := ConnectionAttempts{
		Token: token.Token{
			Type:    token.ConnectionAttempts,
			Literal: "ConnectionAttempts",
		},
		Value: "1",
	}
	fmt.Println(connectionAttempts)
	// Output:
	// ConnectionAttempts 1
}

func ExampleConnectionTimeout_String() {
	connectionTimeout := ConnectionTimeout{
		Token: token.Token{
			Type:    token.ConnectionTimeout,
			Literal: "ConnectionTimeout",
		},
		Value: "0",
	}
	fmt.Println(connectionTimeout)
	// Output:
	// ConnectionTimeout 0
}

func ExampleDynamicForward_String() {
	dynamicForward := DynamicForward{
		Token: token.Token{
			Type:    token.DynamicForward,
			Literal: "DynamicForward",
		},
		Value: "localhost:3333",
	}
	fmt.Println(dynamicForward)
	// Output:
	// DynamicForward localhost:3333
}

func ExampleEscapeChar_String() {
	escapeChar := EscapeChar{
		Token: token.Token{
			Type:    token.EscapeChar,
			Literal: "EscapeChar",
		},
		Value: "~",
	}
	fmt.Println(escapeChar)
	// Output:
	// EscapeChar ~
}

func ExampleExitOnForwardFailure_String() {
	exitOnForwardFailure := ExitOnForwardFailure{
		Token: token.Token{
			Type:    token.ExitOnForwardFailure,
			Literal: "ExitOnForwardFailure",
		},
		Value: "yes",
	}
	fmt.Println(exitOnForwardFailure)
	// Output:
	// ExitOnForwardFailure yes
}

func ExampleFingerprintHash_String() {
	fingerprintHash := FingerprintHash{
		Token: token.Token{
			Type:    token.FingerprintHash,
			Literal: "FingerprintHash",
		},
		Value: "sha256",
	}
	fmt.Println(fingerprintHash)
	// Output:
	// FingerprintHash sha256
}

func ExampleForwardX11_String() {
	forwardX11 := ForwardX11{
		Token: token.Token{
			Type:    token.ForwardX11,
			Literal: "ForwardX11",
		},
		Value: "yes",
	}
	fmt.Println(forwardX11)
	// Output:
	// ForwardX11 yes
}

func ExampleForwardX11Timeout_String() {
	forwardX11Timeout := ForwardX11Timeout{
		Token: token.Token{
			Type:    token.ForwardX11Timeout,
			Literal: "ForwardX11Timeout",
		},
		Value: "0",
	}
	fmt.Println(forwardX11Timeout)
	// Output:
	// ForwardX11Timeout 0
}

func ExampleForwardX11Trusted_String() {
	forwardX11Trusted := ForwardX11Trusted{
		Token: token.Token{
			Type:    token.ForwardX11Trusted,
			Literal: "ForwardX11Trusted",
		},
		Value: "yes",
	}
	fmt.Println(forwardX11Trusted)
	// Output:
	// ForwardX11Trusted yes
}

func ExampleGatewayPorts_String() {
	gatewayPorts := GatewayPorts{
		Token: token.Token{
			Type:    token.GatewayPorts,
			Literal: "GatewayPorts",
		},
		Value: "yes",
	}
	fmt.Println(gatewayPorts)
	// Output:
	// GatewayPorts yes
}

func ExampleGlobalKnownHostsFile_String() {
	globalKnownHostsFile := GlobalKnownHostsFile{
		Token: token.Token{
			Type:    token.GlobalKnownHostsFile,
			Literal: "GlobalKnownHostsFile",
		},
		Value: "/etc/ssh/ssh_known_hosts, /etc/ssh/ssh_known_hosts2, /etc/ssh/ssh_known_hosts3",
	}
	fmt.Println(globalKnownHostsFile)
	// Output:
	// GlobalKnownHostsFile /etc/ssh/ssh_known_hosts, /etc/ssh/ssh_known_hosts2, /etc/ssh/ssh_known_hosts3
}

func ExampleGSSApiAuthentication_String() {
	gssAPIAuthentication := GSSApiAuthentication{
		Token: token.Token{
			Type:    token.GSSAPIAuthentication,
			Literal: "GSSAPIAuthentication",
		},
		Value: "yes",
	}
	fmt.Println(gssAPIAuthentication)
	// Output:
	// GSSAPIAuthentication yes
}

func ExampleGSSApiDelegateCredentials_String() {
	gssAPIDelegateCredentials := GSSApiDelegateCredentials{
		Token: token.Token{
			Type:    token.GSSAPIDelegateCredentials,
			Literal: "GSSAPIDeleteCredentials",
		},
		Value: "yes",
	}
	fmt.Println(gssAPIDelegateCredentials)
	// Output:
	// GSSAPIDeleteCredentials yes
}

func ExampleHostBasedAuthentication_String() {
	hostBasedAuthentication := HostBasedAuthentication{
		Token: token.Token{
			Type:    token.HostbasedAuthentication,
			Literal: "HostbasedAuthentication",
		},
		Value: "yes",
	}
	fmt.Println(hostBasedAuthentication)
	// Output:
	// HostbasedAuthentication yes
}

func ExampleHostBasedKeyTypes_String() {
	hostBasedKeyTypes := HostBasedKeyTypes{
		Token: token.Token{
			Type:    token.HostbasedKeyTypes,
			Literal: "HostbasedKeyTypes",
		},
		Value: "ecdsa-sha2-nistp256-cert-v01@openssh.com, ecdsa-sha2-nistp384-cert-v01@openssh.com",
	}
	fmt.Println(hostBasedKeyTypes)
	// Output:
	// HostbasedKeyTypes ecdsa-sha2-nistp256-cert-v01@openssh.com, ecdsa-sha2-nistp384-cert-v01@openssh.com
}

func ExampleHostKeyAlgorithms_String() {
	hostKeyAlgorithms := HostKeyAlgorithms{
		Token: token.Token{
			Type:    token.HostbasedKeyAlgorithms,
			Literal: "HostKeyAlgorithms",
		},
		Value: "ecdsa-sha2-nistp256-cert-v01@openssh.com, ecdsa-sha2-nistp384-cert-v01@openssh.com",
	}
	fmt.Println(hostKeyAlgorithms)
	// Output:
	// HostKeyAlgorithms ecdsa-sha2-nistp256-cert-v01@openssh.com, ecdsa-sha2-nistp384-cert-v01@openssh.com
}

func ExampleHostKeyAlias_String() {
	 hostKeyAlias := HostKeyAlias{
		Token: token.Token{
			Type:    token.HostKeyAlias,
			Literal: "HostKeyAlias",
		},
		Value: "server1",
	}
	fmt.Println(hostKeyAlias)
	// Output:
	// HostKeyAlias server1
}

func ExampleIdentitiesOnly_String() {
	identitiesOnly := IdentitiesOnly{
		Token: token.Token{
			Type:    token.IdentitiesOnly,
			Literal: "IdentitiesOnly",
		},
		Value: "yes",
	}
	fmt.Println(identitiesOnly)
	// Output:
	// IdentitiesOnly yes
}

func ExampleIdentityAgent_String() {
	identityAgent := IdentityAgent{
		Token: token.Token{
			Type:    token.IdentityAgent,
			Literal: "IdentityAgent",
		},
		Value: "~/.dir/agent.sock",
	}
	fmt.Println(identityAgent)
	// Output:
	// IdentityAgent ~/.dir/agent.sock
}

func ExampleIPQoS_String() {
	ipQoS := IPQoS{
		Token: token.Token{
			Type:    token.IPQoS,
			Literal: "IPQoS",
		},
		Value: "af31",
	}
	fmt.Println(ipQoS)
	// Output:
	// IPQoS af31
}

func ExampleKbdInteractiveAuthentication_String() {
	kbdInteractiveAuthentication := KbdInteractiveAuthentication{
		Token: token.Token{
			Type:    token.KbdInteractiveAuthentication,
			Literal: "KbdInteractiveAuthentication",
		},
		Value: "no",
	}
	fmt.Println(kbdInteractiveAuthentication)
	// Output:
	// KbdInteractiveAuthentication no
}

func ExampleKbdInteractiveDevices_String() {
	kbdInteractiveDevices := KbdInteractiveDevices{
		Token: token.Token{
			Type:    token.KbdInteractiveDevices,
			Literal: "KbdInteractiveDevices",
		},
		Value: "pam, skey, bsdauth",
	}
	fmt.Println(kbdInteractiveDevices)
	// Output:
	// KbdInteractiveDevices pam, skey, bsdauth
}

func ExampleLocalCommand_String() {
	localCommand := LocalCommand{
		Token: token.Token{
			Type:    token.LocalCommand,
			Literal: "LocalCommand",
		},
		Value: "rsync -e ssh %d/testfile %r@%n:testfile",
	}
	fmt.Println(localCommand)
	// Output:
	// LocalCommand rsync -e ssh %d/testfile %r@%n:testfile
}

func ExampleMacs_String() {
	macs := Macs{
		Token: token.Token{
			Type:    token.Macs,
			Literal: "MACs",
		},
		Value: "hmac-sha2-256, hmac-sha2-512, hmac-sha1",
	}
	fmt.Println(macs)
	// Output:
	// MACs hmac-sha2-256, hmac-sha2-512, hmac-sha1
}

func ExampleNoHostAuthentication_String() {
	noHostAuthentication := NoHostAuthentication{
		Token: token.Token{
			Type:    token.NoHostAuthenticationForLocalhost,
			Literal: "NoHostAuthenticationForLocalhost",
		},
		Value: "yes",
	}
	fmt.Println(noHostAuthentication)
	// Output:
	// NoHostAuthenticationForLocalhost yes
}

func ExampleNumberOfPasswordPrompts_String() {
	numberOfPasswordPrompts := NumberOfPasswordPrompts{
		Token: token.Token{
			Type:    token.NumberOfPasswordPrompts,
			Literal: "NumberOfPasswordPrompts",
		},
		Value: "1",
	}
	fmt.Println(numberOfPasswordPrompts)
	// Output:
	// NumberOfPasswordPrompts 1
}

func ExamplePasswordAuthentication_String() {
	passwordAuthentication := PasswordAuthentication{
		Token: token.Token{
			Type:    token.PasswordAuthentication,
			Literal: "PasswordAuthentication",
		},
		Value: "no",
	}
	fmt.Println(passwordAuthentication)
	// Output:
	// PasswordAuthentication no
}

func ExamplePermitLocalCommand_String() {
	permitLocalCommand := PermitLocalCommand{
		Token: token.Token{
			Type:    token.PermitLocalCommand,
			Literal: "PermitLocalCommand",
		},
		Value: "yes",
	}
	fmt.Println(permitLocalCommand)
	// Output:
	// PermitLocalCommand yes
}

func ExamplePCKS11Provider_String() {
	pcks11Provider := PCKS11Provider{
		Token: token.Token{
			Type:    token.Pkcs11Provider,
			Literal: "PKCS11Provider",
		},
		Value: "/usr/lib/i386-linux-gnu/opensc-pkcs11.so",
	}
	fmt.Println(pcks11Provider)
	// Output:
	// PKCS11Provider /usr/lib/i386-linux-gnu/opensc-pkcs11.so
}

func ExamplePreferredAuthentications_String() {
	preferredAuthentications := PreferredAuthentications{
		Token: token.Token{
			Type:    token.PreferredAuthentications,
			Literal: "PreferredAuthentications",
		},
		Value: "password, keyboard-interactive",
	}
	fmt.Println(preferredAuthentications)
	// Output:
	// PreferredAuthentications password, keyboard-interactive
}

func ExampleProxyJump_String() {
	proxyJump := ProxyJump{
		Token: token.Token{
			Type:    token.ProxyJump,
			Literal: "ProxyJump",
		},
		Value: "bastion-host-nickname",
	}
	fmt.Println(proxyJump)
	// Output:
	// ProxyJump bastion-host-nickname
}

func ExampleProxyUserFDPass_String() {
	proxyUserFDPass := ProxyUserFDPass{
		Token: token.Token{
			Type:    token.ProxyUseFdpass,
			Literal: "ProxyUseFdpass",
		},
		Value: "yes",
	}
	fmt.Println(proxyUserFDPass)
	// Output:
	// ProxyUseFdpass yes
}

func ExamplePubkeyAcceptedKeyTypes_String() {
	pubkeyAcceptedKeyTypes := PubkeyAcceptedKeyTypes{
		Token: token.Token{
			Type:    token.PubkeyAcceptedKeyTypes,
			Literal: "PubkeyAcceptedKeyTypes",
		},
		Value: "+ssh-dss",
	}
	fmt.Println(pubkeyAcceptedKeyTypes)
	// Output:
	// PubkeyAcceptedKeyTypes +ssh-dss
}

func ExamplePubkeyAuthentication_String() {
	pubkeyAuthentication := PubkeyAuthentication{
		Token: token.Token{
			Type:    token.PubkeyAuthentication,
			Literal: "PubkeyAuthentication",
		},
		Value: "yes",
	}
	fmt.Println(pubkeyAuthentication)
	// Output:
	// PubkeyAuthentication yes
}

func ExampleRekeyLimit_String() {
	rekeyLimit := RekeyLimit{
		Token: token.Token{
			Type:    token.RekeyLimit,
			Literal: "RekeyLimit",
		},
		Value: "1G",
	}
	fmt.Println(rekeyLimit)
	// Output:
	// RekeyLimit 1G
}

func ExampleRemoteCommand_String() {
	remoteCommand := RemoteCommand{
		Token: token.Token{
			Type:    token.RemoteCommand,
			Literal: "RemoteCommand",
		},
		Value: "cd /tmp && bash",
	}
	fmt.Println(remoteCommand)
	// Output:
	// RemoteCommand cd /tmp && bash
}

func ExampleRemoteForward_String() {
	forward := RemoteForward{
		Token: token.Token{
			Type:    token.RemoteForward,
			Literal: "RemoteForward",
		},
		Value: "55555 localhost:22",
	}
	fmt.Println(forward)
	// Output:
	// RemoteForward 55555 localhost:22
}

func ExampleRequestTTY_String() {
	requestTTY := RequestTTY{
		Token: token.Token{
			Type:    token.RequestTty,
			Literal: "RequestTTY",
		},
		Value: "force",
	}
	fmt.Println(requestTTY)
	// Output:
	// RequestTTY force
}

func ExampleSendEnv_String() {
	sendEnv := SendEnv{
		Token: token.Token{
			Type:    token.SendEnv,
			Literal: "SendEnv",
		},
		Value: "LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES",
	}
	fmt.Println(sendEnv)
	// Output:
	// SendEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
}

func ExampleSetEnv_String() {
	setEnv := SetEnv{
		Token: token.Token{
			Type:    token.SetEnv,
			Literal: "SetEnv",
		},
		Value: "FOO=bar",
	}
	fmt.Println(setEnv)
	// Output:
	// SetEnv FOO=bar
}

func ExampleStreamLocalBindMask_String() {
	streamLocalBindMask := StreamLocalBindMask{
		Token: token.Token{
			Type:    token.StreamLocalBindMask,
			Literal: "StreamLocalBindMask",
		},
		Value: "0177",
	}
	fmt.Println(streamLocalBindMask)
	// Output:
	// StreamLocalBindMask 0177
}

func ExampleStreamLocalBindUnlink_String() {
	streamLocalBindUnlink := StreamLocalBindUnlink{
		Token: token.Token{
			Type:    token.StreamLocalBindUnlink,
			Literal: "StreamLocalBindUnlink",
		},
		Value: "yes",
	}
	fmt.Println(streamLocalBindUnlink)
	// Output:
	// StreamLocalBindUnlink yes
}

func ExampleTCPKeepAlive_String() {
	tcpKeepAlive := TCPKeepAlive{
		Token: token.Token{
			Type:    token.TCPKeepAlive,
			Literal: "TCPKeepAlive",
		},
		Value: "no",
	}
	fmt.Println(tcpKeepAlive)
	// Output:
	// TCPKeepAlive no
}

func ExampleTunnel_String() {
	tunnel := Tunnel{
		Token: token.Token{
			Type:    token.Tunnel,
			Literal: "Tunnel",
		},
		Value: "point-to-point",
	}
	fmt.Println(tunnel)
	// Output:
	// Tunnel point-to-point
}

func ExampleTunnelDevice_String() {
	tunnelDevice := TunnelDevice{
		Token: token.Token{
			Type:    token.TunnelDevice,
			Literal: "TunnelDevice",
		},
		Value: "any",
	}
	fmt.Println(tunnelDevice)
	// Output:
	// TunnelDevice any
}

func ExampleUpdateHostKeys_String() {
	updateHostKeys := UpdateHostKeys{
		Token: token.Token{
			Type:    token.UpdateHostKeys,
			Literal: "UpdateHostKeys",
		},
		Value: "ask",
	}
	fmt.Println(updateHostKeys)
	// Output:
	// UpdateHostKeys ask
}

func ExampleVerifyHostKeyDNS_String() {
	verifyHostKeyDNS := VerifyHostKeyDNS{
		Token: token.Token{
			Type:    token.VerifyHostKeyDNS,
			Literal: "VerifyHostKeyDNS",
		},
		Value: "yes",
	}
	fmt.Println(verifyHostKeyDNS)
	// Output:
	// VerifyHostKeyDNS yes
}

func ExampleVisualHostKey_String() {
	visualHostKey := VisualHostKey{
		Token: token.Token{
			Type:    token.VisualHostKey,
			Literal: "VisualHostKey",
		},
		Value: "yes",
	}
	fmt.Println(visualHostKey)
	// Output:
	// VisualHostKey yes
}

func ExampleXAuthLocation_String() {
	xAuthLocation := XAuthLocation{
		Token: token.Token{
			Type:    token.XauthLocation,
			Literal: "XAuthLocation",
		},
		Value: "/usr/X11R6/bin/xauth",
	}
	fmt.Println(xAuthLocation)
	// Output:
	// XAuthLocation /usr/X11R6/bin/xauth
}

func ExampleControlPath_String() {
	controlPath := ControlPath{
		Token: token.Token{
			Type:    token.ControlPath,
			Literal: "ControlPath",
		},
		Value: "~/.ssh/control-%h-%p-%r",
	}
	fmt.Println(controlPath)
	// Output:
	// ControlPath ~/.ssh/control-%h-%p-%r
}

func ExampleInclude_String() {
	include := Include{
		Token: token.Token{
			Type:    token.Include,
			Literal: "Include",
		},
		Value: "~/.ssh/pi_config",
	}
	fmt.Println(include)
	// Output:
	// Include ~/.ssh/pi_config
}

func ExampleMatch_String() {
	match := Match{
		Token: token.Token{
			Type:    token.Match,
			Literal: "Match",
		},
		Value: "exec \"onsubnet --not 10.10.1.\" host my-server",
	}
	fmt.Println(match)
	// Output:
	// Match exec "onsubnet --not 10.10.1." host my-server
}
