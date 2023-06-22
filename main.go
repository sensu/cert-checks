package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/sensu-community/sensu-plugin-sdk/sensu"
	"github.com/sensu/cert-checks/internal/cert"
	"github.com/sensu/sensu-go/types"
)

// Config represents the check plugin config.
type Config struct {
	sensu.PluginConfig
	Cert       string
	ServerName string
	Influx	   bool
}

var (
	plugin = Config{
		PluginConfig: sensu.PluginConfig{
			Name:     "cert-checks",
			Short:    "Inspects certificate data",
			Keyspace: "sensu.io/plugins/cert-checks/config",
		},
	}

	options = []*sensu.PluginConfigOption{
		{
			Path:      "cert",
			Env:       "CHECK_CERT",
			Argument:  "cert",
			Shorthand: "c",
			Usage:     "URL to certificate. Supports https, tcp, and file schemes",
			Value:     &plugin.Cert,
		},
		{
			Path:      "servername",
			Env:       "CHECK_SERVER_NAME",
			Argument:  "servername",
			Shorthand: "s",
			Usage:     "optional TLS servername extension argument",
			Value:     &plugin.ServerName,
		},
		{
			Path:      "influx",
			Env:       "INFLUX_FORMAT",
			Argument:  "influx",
			Shorthand: "i",
			Default:   false,
			Usage:     "optional Influx format output",
			Value:     &plugin.Influx,
		},
	}
)

func main() {
	useStdin := false
	fi, err := os.Stdin.Stat()
	if err != nil {
		fmt.Printf("Error check stdin: %v\n", err)
		panic(err)
	}
	//Check the Mode bitmask for Named Pipe to indicate stdin is connected
	if fi.Mode()&os.ModeNamedPipe != 0 {
		useStdin = true
	}

	check := sensu.NewGoCheck(&plugin.PluginConfig, options, checkArgs, executeCheck, useStdin)
	check.Execute()
}

func checkArgs(event *types.Event) (int, error) {
	if plugin.Cert == "" {
		return sensu.CheckStateWarning, fmt.Errorf("--cert is required. must be URL to certificate. ex: file:///var/run/app/site.crt, https://dev1.sensu.io:8443, tcp://127.0.0.1:443")
	}
	return sensu.CheckStateOK, nil
}

func executeCheck(event *types.Event) (int, error) {
	ctx := context.Background()
	if plugin.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Second*time.Duration(plugin.Timeout))
		defer cancel()
	}
	metrics, err := cert.CollectMetrics(ctx, plugin.Cert, cert.Config{ServerName: plugin.ServerName, Influx: plugin.Influx})
	if err != nil {
		fmt.Printf("cert-checks failed with error: %s\n", err.Error())
		return sensu.CheckStateCritical, nil
	}
	fmt.Println(metrics.Output())
	return sensu.CheckStateOK, nil
}
