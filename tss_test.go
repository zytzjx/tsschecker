package main

import (
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"howett.net/plist"
)

func TestGenerateArm64eNonce(t *testing.T) {
	generator, err := hex.DecodeString("0807060504030201")
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := sha512.Sum384(generator)
	want := hex.EncodeToString(wantDigest[:32])

	got, err := GenerateArm64eNonce("0x0102030405060708")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("GenerateArm64eNonce() = %s, want %s", got, want)
	}
}

func TestFindMatchingIdentityUsesDeviceClassAndRestoreBehavior(t *testing.T) {
	manifest := &BuildManifest{BuildIdentities: []map[string]interface{}{
		{"Info": map[string]interface{}{"DeviceClass": "d321ap", "RestoreBehavior": "Update"}},
		{"Info": map[string]interface{}{"DeviceClass": "d331pap", "RestoreBehavior": "Erase"}},
	}}

	identity, err := manifest.FindMatchingIdentity("D331PAP", "Erase")
	if err != nil {
		t.Fatal(err)
	}
	info := identity["Info"].(map[string]interface{})
	if info["DeviceClass"] != "d331pap" {
		t.Fatalf("selected DeviceClass = %v, want d331pap", info["DeviceClass"])
	}
	if _, err := manifest.FindMatchingIdentity("d321ap", "Erase"); err == nil {
		t.Fatal("expected an error when no exact erase identity exists")
	}
}

func TestTargetDevicesPreservesHardwareVariants(t *testing.T) {
	variants := 0
	for _, device := range targetDevices {
		if device.productType == "iPhone8,1" {
			variants++
		}
	}
	if variants != 2 {
		t.Fatalf("iPhone8,1 has %d hardware variants, want 2", variants)
	}
}

func TestBuildTSSRequestPayloadFiltersManifestInfo(t *testing.T) {
	client := &TSSClient{
		ECID:    1,
		BoardID: 0x0e,
		ChipID:  0x8020,
		APNonce: make([]byte, 32),
		BuildIdentity: map[string]interface{}{
			"Manifest": map[string]interface{}{
				"iBoot": map[string]interface{}{
					"Digest":  []byte{1, 2, 3},
					"Trusted": true,
					"Info": map[string]interface{}{
						"RestoreRequestRules": []interface{}{map[string]interface{}{
							"Conditions": map[string]interface{}{"ApRequiresImage4": true},
							"Actions":    map[string]interface{}{"EPRO": true},
						}},
					},
				},
				"Cryptex1,DeveloperDiskImage": map[string]interface{}{
					"Digest": []byte{4, 5, 6},
					"Info":   map[string]interface{}{"Personalize": true},
				},
			},
		},
	}

	payload, err := client.BuildTSSRequestPayload()
	if err != nil {
		t.Fatal(err)
	}
	var request map[string]interface{}
	if _, err := plist.Unmarshal(payload, &request); err != nil {
		t.Fatal(err)
	}

	entry, ok := request["iBoot"].(map[string]interface{})
	if !ok {
		t.Fatal("TSS request is missing the iBoot component")
	}
	if _, exists := entry["Info"]; exists {
		t.Fatal("BuildManifest Info metadata must not be sent as a TSS component tag")
	}
	if entry["EPRO"] != true {
		t.Fatalf("RestoreRequestRules did not set EPRO: %v", entry["EPRO"])
	}
	if _, exists := request["Cryptex1,DeveloperDiskImage"]; exists {
		t.Fatal("Cryptex components must not be included in the AP ticket request")
	}
	if request["@ApImg4Ticket"] != true || request["@BBTicket"] != true {
		t.Fatal("request is missing IMG4 ticket flags")
	}
	if got, ok := request["SepNonce"].([]byte); !ok || len(got) != 20 {
		t.Fatalf("SepNonce has invalid type or length: %T, %v", request["SepNonce"], request["SepNonce"])
	}
}
