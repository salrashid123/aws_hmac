// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package credentials

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"

	"github.com/hashicorp/vault/api"
)

type VaultConfig struct {
	VaultToken  string
	VaultPath   string
	VaultCAcert string
	VaultAddr   string
}

type HMACCredentialConfig struct {
	VaultConfig  VaultConfig
	AccessKeyID  string
	SessionToken string
}

type HMACCredential struct {
	refreshMutex *sync.Mutex
	VaultConfig  VaultConfig
	AccessKeyID  string
	SessionToken string
}

const ()

var ()

func NewHMACCredential(cfg *HMACCredentialConfig) (*HMACCredential, error) {

	return &HMACCredential{
		refreshMutex: &sync.Mutex{},
		VaultConfig:  cfg.VaultConfig,
		AccessKeyID:  cfg.AccessKeyID,
		SessionToken: cfg.SessionToken,
	}, nil
}

func (ts *HMACCredential) MAC(msg []byte) ([]byte, error) {

	ts.refreshMutex.Lock()
	defer ts.refreshMutex.Unlock()

	if ts.VaultConfig.VaultToken != "" {
		caCertPool := x509.NewCertPool()
		if ts.VaultConfig.VaultCAcert != "" {
			caCert, err := ioutil.ReadFile(ts.VaultConfig.VaultCAcert)
			if err != nil {
				return []byte(""), err
			}
			caCertPool.AppendCertsFromPEM(caCert)
		}

		config := &api.Config{
			Address: ts.VaultConfig.VaultAddr,
			HttpClient: &http.Client{Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: caCertPool,
				},
			}},
		}

		client, err := api.NewClient(config)
		if err != nil {
			return []byte(""), err
		}

		client.SetToken(ts.VaultConfig.VaultToken)

		data := map[string]interface{}{
			"input": base64.StdEncoding.EncodeToString(msg),
		}

		secret, err := client.Logical().Write(ts.VaultConfig.VaultPath, data)
		if err != nil {
			//fmt.Printf("VaultToken:  Unable to read resource at path [%s] error: %v", ts.VaultConfig.VaultPath, err)
			return []byte(""), err
		}

		if _, ok := secret.Data["hmac"]; !ok {
			return nil, fmt.Errorf("hmac missing  key")
		}
		hmacResponseString, ok := secret.Data["hmac"].(string)
		if !ok {
			return nil, fmt.Errorf("hmac error casting response to string")
		}

		macOut := strings.TrimPrefix(hmacResponseString, "vault:v1:")
		macEncoded, err := base64.StdEncoding.DecodeString(macOut)
		if !ok {
			return nil, err
		}
		//macOut := []byte(strings.TrimPrefix(hmacResponseString, "vault:v1:"))

		return macEncoded, nil
	}

	return []byte(""), errors.New("Unknown HMAC Provider")
}
