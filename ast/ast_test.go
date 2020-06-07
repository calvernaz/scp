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