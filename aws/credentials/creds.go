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
	"github.com/miekg/pkcs11"
)

type TinkConfig struct {
	KmsBackend tink.AEAD
	JSONBytes  []byte
	a          tink.MAC
}

type PKCSConfig struct {
	Library string
	Slot    int
	Label   string
	Id      []byte
	PIN     string
}

type HMACCredentialConfig struct {
	TinkConfig   TinkConfig
	PKCSConfig   PKCSConfig
	AccessKeyID  string
	SessionToken string
}

type HMACCredential struct {
	refreshMutex *sync.Mutex
	TinkConfig   TinkConfig
	PKCSConfig   PKCSConfig
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

	if cfg.PKCSConfig.Library != "" {

		p := pkcs11.New(cfg.PKCSConfig.Library)
		err := p.Initialize()
		if err != nil {
			return &HMACCredential{}, err
		}

		defer p.Destroy()
		defer p.Finalize()

		slots, err := p.GetSlotList(true)
		if err != nil {
			return &HMACCredential{}, err
		}

		session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			return &HMACCredential{}, err
		}
		defer p.CloseSession(session)

		err = p.Login(session, pkcs11.CKU_USER, cfg.PKCSConfig.PIN)
		if err != nil {
			return &HMACCredential{}, err
		}
		defer p.Logout(session)

		_, err = p.GetInfo()
		if err != nil {
			return &HMACCredential{}, err
		}

	}

	return &HMACCredential{
		refreshMutex: &sync.Mutex{},
		TinkConfig:   cfg.TinkConfig,
		PKCSConfig:   cfg.PKCSConfig,
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

	if ts.PKCSConfig.Library != "" {

		p := pkcs11.New(ts.PKCSConfig.Library)
		err := p.Initialize()
		if err != nil {
			return []byte(""), err
		}

		slots, err := p.GetSlotList(true)
		if err != nil {
			return []byte(""), err
		}

		session, err := p.OpenSession(slots[ts.PKCSConfig.Slot], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			return []byte(""), err
		}
		defer p.CloseSession(session)

		err = p.Login(session, pkcs11.CKU_USER, ts.PKCSConfig.PIN)
		if err != nil {
			return []byte(""), err
		}
		defer p.Logout(session)

		ktemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, ts.PKCSConfig.Id),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, ts.PKCSConfig.Label),
		}

		if err := p.FindObjectsInit(session, ktemplate); err != nil {
			return []byte(""), err
		}
		ik, _, err := p.FindObjects(session, 1)
		if err != nil {
			return []byte(""), err
		}
		if err = p.FindObjectsFinal(session); err != nil {
			return []byte(""), err
		}

		err = p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_HMAC, nil)}, ik[0])
		if err != nil {
			return []byte(""), err
		}

		// Sign 'msg'
		return p.Sign(session, msg)

	}
	return []byte(""), errors.New("Unknown HMAC Provider")
}
