package skanpostback

import (
	"errors"
	"testing"
)

func TestVerify(t *testing.T) {
	validPostbackV10 := []byte(`
{
  "ad-network-id": "su67r6k2v3.skadnetwork",
  "app-id": 1176027022,
  "attribution-signature": "MDMCGELMEaJCS0y1JXqjZujcMXdJel8boLV6PAIXFNKYjzROJY2CxAmU+HoPQfTJCyjoS6k=",
  "campaign-id": 51,
  "redownload": false,
  "transaction-id": "583e867c-0bc5-4980-8766-6d8cf992f24a",
  "version": "1.0"
}
`)

	validPostbackV20 := []byte(`
{
  "ad-network-id": "v9wttpbfk9.skadnetwork",
  "app-id": 1176027022,
  "attribution-signature": "MDQCGDYZvzXjCRDEcFjJu2xd4kaOPwK+sJpUbgIYZRiWFh0Lpz7KFnF3qrXdyl9sAG8j6gne",
  "campaign-id": 75,
  "conversion-value": 18,
  "redownload": true,
  "transaction-id": "c4a69044-1c85-4755-9e25-97d8daa30c55",
  "version": "2.0"
}
`)

	validPostbackV21 := []byte(`
{
	"version": "2.1",
	"ad-network-id": "com.example",
	"campaign-id": 42,
	"transaction-id": "6aafb7a5-0170-41b5-bbe4-fe71dedf1e28",
	"app-id": 525463029,
	"attribution-signature": "MEUCID6rbq3qt4GvFaAaynh5/LAcvn1d8CQTRhrZhLIxLKntAiEAo7IrvoMw6u2qDg6Tr5vIsEHXjlLkPlCOL0ojJcEh3Qw=",
	"redownload": true,
	"source-app-id": 1234567891,
	"conversion-value": 20
}
`)

	validPostbackV22 := []byte(`
{
	"version": "2.2",
	"ad-network-id": "com.example",
	"campaign-id": 42,
	"transaction-id": "6aafb7a5-0170-41b5-bbe4-fe71dedf1e28",
	"app-id": 525463029,
	"attribution-signature": "MEYCIQDTuQ1Z4Tpy9D3aEKbxLl5J5iKiTumcqZikuY/AOD2U7QIhAJAaiAv89AoquHXJffcieEQXdWHpcV8ZgbKN0EwV9/sY",
	"redownload": true,
	"source-app-id": 1234567891,
	"fidelity-type": 1,
	"conversion-value": 20
}
`)

	validPostbackV30 := []byte(`
{
	"version": "3.0",
	"ad-network-id": "example123.skadnetwork",
	"campaign-id": 42,
	"transaction-id": "f9ac267a-a889-44ce-b5f7-0166d11461f0",
	"app-id": 525463029,
	"attribution-signature": "MEUCIQDDetUtkyc/MiQvVJ5I6HIO1E7l598572Wljot2Onzd4wIgVJLzVcyAV+TXksGNoa0DTMXEPgNPeHCmD4fw1ABXX0g=",
	"redownload": true,
	"fidelity-type": 1,
	"did-win": false
}
`)

	invalidPostback := []byte(`
{
	"version": "3.0",
	"ad-network-id": "example123.skadnetwork",
	"campaign-id": "42",
	"transaction-id": "f9ac267a-a889-44ce-b5f7-0166d11461f0",
	"app-id": 525463029,
	"attribution-signature": "MEUCIQDDetUtkyc/MiQvVJ5I6HIO1E7l598572Wljot2Onzd4wIgVJLzVcyAV+TXksGNoa0DTMXEPgNPeHCmD4fw1ABXX0g=",
	"redownload": true,
	"fidelity-type": 1,
	"did-win": false
}
`) // 'campaign-id' should be a number, not string

	validIronSource := []byte(`
{
	"transaction-id":"240b7588-90a3-4ecc-84c6-4e5263395c40",
	"ad-network-id":"su67r6k2v3.skadnetwork",
	"timestamp":1613095729,
	"campaign-id":92,
	"conversion-value":0,
	"redownload":false,
	"version":"2.1",
	"source-app-id":1299956969,
	"attribution-signature":"MEUCIQDiGkZ57TN2NX0s6gQ9MZiD2O8DXJga2kJbzxcpqq1cawIgVMTTh58UjhngI1aY+sBUvk60iwa7t++IZIa0lB4gS2k=",
	"app-id":1196764367
}`)

	validTikTok := []byte(`
{
	"version":"2.1",
	"ad-network-id":"mj797d8u6f.skadnetwork",
	"campaign-id":3,
	"transaction-id":"00877faf-84ac-459c-b1a2-5301bf4452d8",
	"app-id":1434505322,
	"attribution-signature":"MEUCIHDlkRyY8uA78H5vKLw1chf192FSBnbDnQMxUXJdmtPrAiEAuqCVM63RZxpkexKKrFCgfkM5aLZ4mMZkRrkL0ivovNc=",
	"redownload":false,
	"adjust-campaign":"a_campaign",
	"adjust-campaign-id":"112233445566",
	"adjust-adgroup":"a_group_uid",
	"adjust-adgroup-id":"112233445566",
	"timestamp":1622794663
}`)

	tt := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid postback (v1.0)",
			data:    validPostbackV10,
			wantErr: false,
		},
		{
			name:    "valid postback (v2.0)",
			data:    validPostbackV20,
			wantErr: false,
		},
		{
			name:    "valid postback (v2.1)",
			data:    validPostbackV21,
			wantErr: false,
		},
		{
			name:    "valid postback (v2.2)",
			data:    validPostbackV22,
			wantErr: false,
		},
		{
			name:    "valid postback (v3.0)",
			data:    validPostbackV30,
			wantErr: false,
		},
		{
			name:    "invalid postback",
			data:    invalidPostback,
			wantErr: true,
		},
		{
			name:    "valid postback (iron source)",
			data:    validIronSource,
			wantErr: false,
		},
		{
			name:    "valid postback (tiktok)",
			data:    validTikTok,
			wantErr: false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			err := Verify(tc.data)

			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("Verify() gotErr = %v, wantErr %v, err: %v", gotErr, tc.wantErr, err)
			}
		})
	}
}

func TestVerify_Errors(t *testing.T) {
	tt := []struct {
		name string
		data []byte
		err  error
	}{
		{
			name: "invalid json",
			data: []byte("hi"),
			err:  ErrBadData,
		},
		{
			name: "missing 'attribution-signature' json key",
			data: []byte(`{"my-name"":"john"}`),
			err:  ErrBadData,
		},
		{
			name: "malformed signature",
			data: []byte(`{"attribution-signature"":"i_should_be_base64_decoded_string"}`),
			err:  ErrBadData,
		},
		{
			name: "invalid signature (missing fields)",
			data: []byte(`{"attribution-signature": "MDMCGELMEaJCS0y1JXqjZujcMXdJel8boLV6PAIXFNKYjzROJY2CxAmU+HoPQfTJCyjoS6k=","version": "1.0"}`),
			err:  ErrInvalidData,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			err := Verify(tc.data)

			if !errors.Is(err, tc.err) {
				t.Errorf("Verify() should return %v, got %v", tc.err, err)
			}
		})
	}
}
