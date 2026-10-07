package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"howett.net/plist"
)

type TSSClient struct {
	ECID          uint64
	BoardID       uint64
	ChipID        uint64
	APNonce       []byte
	BuildIdentity map[string]interface{}
}

func (c *TSSClient) BuildTSSRequestPayload() ([]byte, error) {
	manifest, ok := c.BuildIdentity["Manifest"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("the specified BuildIdentity does not contain a valid Manifest")
	}
	if len(c.APNonce) != 32 {
		return nil, fmt.Errorf("A12 APNonce length must be 32 bytes, current length is` %d", len(c.APNonce))
	}

	uuid, err := newTSSUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate TSS UUID: %w", err)
	}
	sepNonce := make([]byte, 20)
	if _, err := rand.Read(sepNonce); err != nil {
		return nil, fmt.Errorf("failed to generate SEP nonce: %w", err)
	}

	parameters := map[string]interface{}{
		"ApBoardID":        c.BoardID,
		"ApChipID":         c.ChipID,
		"ApECID":           c.ECID,
		"ApNonce":          c.APNonce,
		"ApSepNonce":       sepNonce,
		"ApProductionMode": true,
		"ApSecurityMode":   true,
		"ApSupportsImg4":   true,
		"Manifest":         manifest,
	}
	for _, key := range []string{
		"UniqueBuildID", "Ap,OSLongVersion", "Ap,OSReleaseType", "Ap,ProductType",
		"Ap,SDKPlatform", "Ap,SikaFuse", "Ap,Target", "Ap,TargetType",
		"ApSecurityDomain", "Ap,ProductMarketingVersion", "PearlCertificationRootPub",
		"NeRDEpoch", "AllowNeRDBoot", "Ap,Timestamp",
	} {
		if value, exists := c.BuildIdentity[key]; exists {
			parameters[key] = normalizeTSSValue(value)
		}
	}
	parameters["ApBoardID"] = c.BoardID
	parameters["ApChipID"] = c.ChipID
	parameters["ApECID"] = c.ECID
	parameters["ApSecurityDomain"] = uint64(1)

	request := map[string]interface{}{
		"@HostPlatformInfo": "windows",
		"@VersionInfo":      "libauthinstall_Win-1104.0.9",
		"@UUID":             uuid,
		"@ApImg4Ticket":     true,
		"@BBTicket":         true,
		"ApBoardID":         parameters["ApBoardID"],
		"ApChipID":          parameters["ApChipID"],
		"ApECID":            parameters["ApECID"],
		"ApSecurityDomain":  parameters["ApSecurityDomain"],
		"ApNonce":           parameters["ApNonce"],
		"SepNonce":          parameters["ApSepNonce"],
		"ApProductionMode":  parameters["ApProductionMode"],
		"ApSecurityMode":    parameters["ApSecurityMode"],
	}
	for _, key := range []string{
		"UniqueBuildID", "Ap,OSLongVersion", "Ap,OSReleaseType", "Ap,ProductType",
		"Ap,SDKPlatform", "Ap,SikaFuse", "Ap,Target", "Ap,TargetType",
		"Ap,ProductMarketingVersion", "PearlCertificationRootPub", "NeRDEpoch",
		"AllowNeRDBoot", "Ap,Timestamp",
	} {
		if value, exists := parameters[key]; exists {
			request[key] = value
		}
	}

	if manifest, ok := c.BuildIdentity["Manifest"].(map[string]interface{}); ok {
		for key, value := range manifest {
			if key == "BasebandFirmware" || key == "SE,UpdatePayload" || key == "BaseSystem" || key == "Diags" || key == "Ap,ExclaveOS" || strings.HasPrefix(key, "Cryptex1,") {
				continue
			}
			entry, ok := value.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("BuildIdentity Manifest entry %s has an invalid format", key)
			}
			info, ok := entry["Info"].(map[string]interface{})
			if !ok {
				continue
			}
			rules, hasRules := info["RestoreRequestRules"].([]interface{})
			trusted, _ := entry["Trusted"].(bool)
			if !hasRules && !trusted {
				continue
			}

			tssEntry := make(map[string]interface{}, len(entry))
			for entryKey, entryValue := range entry {
				if entryKey != "Info" {
					tssEntry[entryKey] = entryValue
				}
			}
			if hasRules {
				applyTSSRestoreRequestRules(tssEntry, parameters, rules)
			}
			if trusted {
				if _, exists := tssEntry["Digest"]; !exists {
					tssEntry["Digest"] = []byte{}
				}
			}
			request[key] = tssEntry
		}
	}

	return plist.Marshal(request, plist.XMLFormat)
}

func newTSSUUID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := strings.ToUpper(hex.EncodeToString(value))
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

func normalizeTSSValue(value interface{}) interface{} {
	text, ok := value.(string)
	if !ok || !strings.HasPrefix(text, "0x") {
		return value
	}
	number, err := strconv.ParseUint(text[2:], 16, 64)
	if err != nil {
		return value
	}
	return number
}

func applyTSSRestoreRequestRules(entry, parameters map[string]interface{}, rules []interface{}) {
	for _, value := range rules {
		rule, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		conditions, ok := rule["Conditions"].(map[string]interface{})
		if !ok {
			continue
		}
		matches := true
		for key, expected := range conditions {
			parameterKey := key
			switch key {
			case "ApRawProductionMode", "ApCurrentProductionMode":
				parameterKey = "ApProductionMode"
			case "ApRawSecurityMode":
				parameterKey = "ApSecurityMode"
			case "ApRequiresImage4":
				parameterKey = "ApSupportsImg4"
			case "ApDemotionPolicyOverride":
				parameterKey = "DemotionPolicy"
			}
			actual, exists := parameters[parameterKey]
			if !exists || !reflect.DeepEqual(actual, expected) {
				matches = false
				break
			}
		}
		if !matches {
			continue
		}
		actions, ok := rule["Actions"].(map[string]interface{})
		if !ok {
			continue
		}
		for key, action := range actions {
			if number, ok := action.(uint64); ok && number == 255 {
				continue
			}
			entry[key] = action
		}
	}
}

func SendToAppleTSS(payload []byte) ([]byte, error) {
	endpoint := "https://gs.apple.com/TSS/controller?action=2"
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "TSSChecker/Go-Engine")
	req.Header.Set("Content-Type", "text/xml; charset=\"utf-8\"")
	req.Header.Set("Cache-Control", "no-cache")

	// 跳过 TLS 证书不匹配问题
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}
