package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"
)

// GenerateArm64eNonce derives the 32-byte APNonce used by A12 devices.
func GenerateArm64eNonce(generatorHex string) (string, error) {
	generatorHex = strings.TrimPrefix(strings.TrimSpace(generatorHex), "0x")
	generator, err := hex.DecodeString(generatorHex)
	if err != nil || len(generator) != 8 {
		return "", fmt.Errorf("Invalid Generator (requires 8-byte Hex)")
	}
	for left, right := 0, len(generator)-1; left < right; left, right = left+1, right-1 {
		generator[left], generator[right] = generator[right], generator[left]
	}

	hash := sha512.Sum384(generator)
	return hex.EncodeToString(hash[:32]), nil
}

// EncryptCryptex1Nonce 使用 0x8A4 Key 加密 Cryptex Seed (iOS 16+)
func EncryptCryptex1Nonce(keyHex string, cryptexSeedHex string) (string, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 16 {
		return "", fmt.Errorf("Invalid 0x8A4 Key (requires 16-byte Hex)")
	}

	seed, err := hex.DecodeString(cryptexSeedHex)
	if err != nil || len(seed) != 16 {
		return "", fmt.Errorf("Invalid Cryptex Seed (requires 16-byte Hex)")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, 16)
	iv := make([]byte, 16)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, seed)

	// Cryptex1 采用 SHA-384 截取前 32 字节
	hash := sha512.Sum384(ciphertext)
	return hex.EncodeToString(hash[:32]), nil
}
