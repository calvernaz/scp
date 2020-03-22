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
		want ast.Statement
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
			want:  &ast.User{
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
			want:  &ast.UseKeyChain{
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
			want:  &ast.LocalForward{
				Token: token.Token{
					Type:    token.LOCAL_FORWARD,
					Literal: "LocalForward",
				},
				Value: "8443 127.0.0.1:443",
			},
		},
		{
			input: "ControlMaster yes",
			want:  &ast.ControlMaster{
				Token: token.Token{
					Type:    token.CONTROL_MASTER,
					Literal: "ControlMaster",
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
