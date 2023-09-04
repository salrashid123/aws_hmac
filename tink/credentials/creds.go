// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package credentials

import (
	"bytes"
	"encoding/json"
	"errors"
	"sync"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/tink"
)

type TinkConfig struct {
	KmsBackend tink.AEAD
	JSONBytes  []byte
	a          tink.MAC
}

type HMACCredentialConfig struct {
	TinkConfig   TinkConfig
	AccessKeyID  string
	SessionToken string
}

type HMACCredential struct {
	refreshMutex *sync.Mutex
	TinkConfig   TinkConfig
	AccessKeyID  string
	SessionToken string
}

const ()

var ()

func NewHMACCredential(cfg *HMACCredentialConfig) (*HMACCredential, error) {

	if cfg.TinkConfig.JSONBytes != nil && cfg.TinkConfig.KmsBackend != nil {
		// Read the json keyset bytes using the KMS backend
		// this is what you would read from disk...its an encrypted with kms so its safe to do so
		var prettyJSON bytes.Buffer
		err := json.Indent(&prettyJSON, cfg.TinkConfig.JSONBytes, "", "\t")
		if err != nil {
			return &HMACCredential{}, err
		}

		r := keyset.NewJSONReader(&prettyJSON)
		kh1, err := keyset.Read(r, cfg.TinkConfig.KmsBackend)
		if err != nil {
			return &HMACCredential{}, err
		}
		// Construct MAC
		a, err := mac.New(kh1)
		if err != nil {
			return &HMACCredential{}, err
		}
		cfg.TinkConfig.a = a
	}

	return &HMACCredential{
		refreshMutex: &sync.Mutex{},
		TinkConfig:   cfg.TinkConfig,
		AccessKeyID:  cfg.AccessKeyID,
		SessionToken: cfg.SessionToken,
	}, nil
}

func (ts *HMACCredential) MAC(msg []byte) ([]byte, error) {

	ts.refreshMutex.Lock()
	defer ts.refreshMutex.Unlock()

	if ts.TinkConfig.a != nil {
		return ts.TinkConfig.a.ComputeMAC(msg)
	}

	return []byte(""), errors.New("Unknown HMAC Provider")
}
