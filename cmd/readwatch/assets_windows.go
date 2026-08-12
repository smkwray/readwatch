//go:build windows

package main

import _ "embed"

var (
	//go:embed resources/ReadWatch.ico
	embeddedIcon []byte

	//go:embed resources/ReadWatch.exe.manifest
	embeddedManifest []byte
)

func embeddedAsset(name string) []byte {
	switch name {
	case "ReadWatch.ico":
		return embeddedIcon
	case "ReadWatch.exe.manifest":
		return embeddedManifest
	default:
		return nil
	}
}
