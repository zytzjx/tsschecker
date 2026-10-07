package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"strings"

	"howett.net/plist"
)

type BuildManifest struct {
	BuildIdentities       []map[string]interface{} `plist:"BuildIdentities"`
	ProductVersion        string                   `plist:"ProductVersion"`
	ProductBuildVersion   string                   `plist:"ProductBuildVersion"`
	SupportedProductTypes []string                 `plist:"SupportedProductTypes"`
}

func ReadManifestFromIPSW(ipswPath string) (*BuildManifest, error) {
	r, err := zip.OpenReader(ipswPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open ipsw file: %w", err)
	}
	defer r.Close()

	var manifestFile *zip.File
	for _, f := range r.File {
		if f.Name == "BuildManifest.plist" {
			manifestFile = f
			break
		}
	}

	if manifestFile == nil {
		return nil, fmt.Errorf("BuildManifest.plist not found in ipsw package")
	}

	rc, err := manifestFile.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open BuildManifest.plist: %w", err)
	}
	defer rc.Close()

	manifestData, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to read BuildManifest.plist: %w", err)
	}

	var manifest BuildManifest
	decoder := plist.NewDecoder(bytes.NewReader(manifestData))
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("failed to parse BuildManifest.plist: %w", err)
	}

	return &manifest, nil
}

// FindMatchingIdentity selects the requested device class and restore behavior.
func (bm *BuildManifest) FindMatchingIdentity(deviceClass, restoreBehavior string) (map[string]interface{}, error) {
	for _, identity := range bm.BuildIdentities {
		info, ok := identity["Info"].(map[string]interface{})
		if !ok {
			continue
		}
		class, _ := info["DeviceClass"].(string)
		behavior, _ := info["RestoreBehavior"].(string)
		if strings.EqualFold(class, deviceClass) && strings.EqualFold(behavior, restoreBehavior) {
			return identity, nil
		}
	}

	return nil, fmt.Errorf("BuildManifest does not contain a BuildIdentity with DeviceClass=%s and RestoreBehavior=%s", deviceClass, restoreBehavior)
}
