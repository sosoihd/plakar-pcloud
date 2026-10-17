package main

import (
	"os"

	sdk "github.com/PlakarKorp/go-kloset-sdk"
	pcloud "github.com/sosoihd/plakar-pcloud"
)

func main() {
	sdk.EntrypointExporter(os.Args, pcloud.NewExporter)
}
