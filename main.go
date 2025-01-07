package main

import (
	"context"
	"flag"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/myklst/terraform-provider-st-byteplus/byteplus"
)

// Provider documentation generation.
//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate --provider-name st-alicloud

func main() {
	providerAddress := os.Getenv("PROVIDER_LOCAL_PATH")
	if providerAddress == "" {
		providerAddress = "registry.terraform.io/myklst/st-byteplus"
	}
	providerserver.Serve(context.Background(), byteplus.New, providerserver.ServeOpts{
		Address: providerAddress,
	})
}
