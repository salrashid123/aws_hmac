// Attribution: https://github.com/aws/aws-sdk-go-v2/blob/main/aws/signer

package signer

import (
	"bytes"
	"encoding/json"
	"errors"
	"sync"

	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac"
	"github.com/tink-crypto/tink-go/v2/tink"
)

type TinkConfig struct {
	KmsBackend tink.AEAD
	JSONBytes  []byte
	a          tink.MAC
}

type TinkSignerConfig struct {
	TinkConfig   TinkConfig
	AccessKeyID  string
	SessionToken string
}

type TinkSigner struct {
	refreshMutex *sync.Mutex
	TinkConfig   TinkConfig
	AccessKeyID  string
	SessionToken string
}

var ()

func NewTinkSigner(cfg *TinkSignerConfig) (*TinkSigner, error) {

	if cfg.TinkConfig.JSONBytes != nil && cfg.TinkConfig.KmsBackend != nil {
		// Read the json keyset bytes using the KMS backend
		// this is what you would read from disk...its an encrypted with kms so its safe to do so
		var prettyJSON bytes.Buffer
		err := json.Indent(&prettyJSON, cfg.TinkConfig.JSONBytes, "", "\t")
		if err != nil {
			return &TinkSigner{}, err
		}

		r := keyset.NewJSONReader(&prettyJSON)
		kh1, err := keyset.Read(r, cfg.TinkConfig.KmsBackend)
		if err != nil {
			return &TinkSigner{}, err
		}
		// Construct MAC
		a, err := mac.New(kh1)
		if err != nil {
			return &TinkSigner{}, err
		}
		cfg.TinkConfig.a = a
	}

	return &TinkSigner{
		refreshMutex: &sync.Mutex{},
		TinkConfig:   cfg.TinkConfig,
		AccessKeyID:  cfg.AccessKeyID,
		SessionToken: cfg.SessionToken,
	}, nil
}

func (s *TinkSigner) MAC(msg []byte) ([]byte, error) {

	s.refreshMutex.Lock()
	defer s.refreshMutex.Unlock()

	if s.TinkConfig.a != nil {
		return s.TinkConfig.a.ComputeMAC(msg)
	}

	return []byte(""), errors.New("Unknown HMAC Provider")
}
