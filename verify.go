package skanpostback

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	gx509 "github.com/google/certificate-transparency-go/x509"
)

const (
	applePublicKey       = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWdp8GPcGqmhgzEFj9Z2nSpQVddayaPe4FMzqM9wib1+aHaaIzoHoLN9zW4K8y4SPykE3YVK3sVqW6Af0lfx3gg=="
	applePublicKeyLegacy = "MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEMyHD625uvsmGq4C43cQ9BnfN2xslVT5V1nOmAMP6qaRRUll3PB1JYmgSm+62sosG"

	sep = "\u2063"
)

// Verify checks `attribution-signature` according to Apple combining parameters rules.
// https://developer.apple.com/documentation/storekit/skadnetwork/verifying_an_install-validation_postback
func Verify(data []byte) error {
	var pb map[string]interface{}
	if err := json.Unmarshal(data, &pb); err != nil {
		return fmt.Errorf("unmarshal json: %w", err)
	}

	attributionSignature, ok := pb["attribution-signature"].(string)
	if !ok {
		return fmt.Errorf("missing 'attribution-signature' key")
	}

	decodedSignature, err := base64.StdEncoding.DecodeString(attributionSignature)
	if err != nil {
		return fmt.Errorf("base64 decode: %w", err)
	}

	var publicKey string

	version, ok := pb["version"].(string)
	if ok {
		switch version {
		case "1.0", "2.0":
			publicKey = applePublicKeyLegacy
		default:
			publicKey = applePublicKey
		}
	}

	decodedKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}

	pub, err := gx509.ParsePKIXPublicKey(decodedKey)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	hash := sha256.Sum256(signature(pb))

	var esig struct {
		R, S *big.Int
	}

	if _, err := asn1.Unmarshal(decodedSignature, &esig); err != nil {
		return fmt.Errorf("unmarshal asn1: %w", err)
	}

	if !ecdsa.Verify(pub.(*ecdsa.PublicKey), hash[:], esig.R, esig.S) {
		return fmt.Errorf("signature not valid")
	}

	return nil
}

// signature combines parameters with separator and returns signature.
func signature(pb map[string]interface{}) []byte {
	var params []string

	version, ok := pb["version"].(string)
	if ok && version != "1.0" {
		params = append(params, version)
	}

	adNetworkId, ok := pb["ad-network-id"].(string)
	if ok {
		params = append(params, adNetworkId)
	}

	campaignId, ok := pb["campaign-id"].(float64)
	if ok {
		params = append(params, fmt.Sprintf("%d", int(campaignId)))
	}

	appId, ok := pb["app-id"].(float64)
	if ok {
		params = append(params, fmt.Sprintf("%d", int(appId)))
	}

	transactionId, ok := pb["transaction-id"].(string)
	if ok {
		params = append(params, transactionId)
	}

	redownload, ok := pb["redownload"].(bool)
	if ok && version != "1.0" {
		params = append(params, strconv.FormatBool(redownload))
	}

	sourceAppId, ok := pb["source-app-id"].(float64)
	if ok {
		params = append(params, fmt.Sprintf("%d", int(sourceAppId)))
	}

	fidelityType, ok := pb["fidelity-type"].(float64)
	if ok {
		params = append(params, fmt.Sprintf("%d", int(fidelityType)))
	}

	didWin, ok := pb["did-win"].(bool)
	if ok {
		params = append(params, strconv.FormatBool(didWin))
	}

	sig := strings.Join(params, sep)

	return []byte(sig)
}
