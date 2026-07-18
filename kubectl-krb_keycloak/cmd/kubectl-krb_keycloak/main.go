package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/pliu/kubectl-plugins/kubectl-krb_keycloak/internal/app"
)

func main() {
	os.Exit(run())
}

func run() int {
	config, err := app.ParseConfig(os.Args[1:], os.LookupEnv, os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err == nil {
		err = app.Run(context.Background(), config, os.Stdin, os.Getenv("KUBERNETES_EXEC_INFO"), os.Stdout, os.Stderr)
	}
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "kubectl-krb_keycloak: %s\n", err)
		return 1
	}
	return 0
}
