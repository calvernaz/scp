package main

import (
	"fmt"
	"io/ioutil"
	"log"

	"github.com/calvernaz/scp/lexer"
	"github.com/calvernaz/scp/parser"
)

func main() {
	bytes, err := ioutil.ReadFile("example/config")
	if err != nil {
		log.Fatal(err)
	}

	l := lexer.New(string(bytes))
	p := parser.New(l)

	config := p.ParseConfig()
	for _, cfg := range config.Statements {
		fmt.Println(cfg.String())
	}

	// ControlPath ~/.ssh/tmp/%r@%h:%p
	// ControlPersist 60m
	// TCPKeepAlive true
	// ServerAliveInterval 15
	// ServerAliveCountMax 30
	// Host *.wm.az.*.* 10.128.*.* 10.13?.*.*
	//  ControlMaster auto
	//  StrictHostKeyChecking no

}
