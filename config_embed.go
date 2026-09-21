package main

import _ "embed"

// defaultConfig is embedded so a standalone tshc binary can initialize its
// configuration without a sidecar file.
//
//go:embed teleports.yaml
var defaultConfig []byte
