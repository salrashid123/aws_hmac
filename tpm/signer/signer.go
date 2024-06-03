// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package signer

import (
	"fmt"
	"io"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type TPMConfig struct {
	TPMDevice        io.ReadWriteCloser
	AuthHandle       tpm2.AuthHandle
	Auth             tpm2.TPM2BAuth
	EncryptionHandle tpm2.TPMHandle   // (optional) handle to use for transit encryption
	EncryptionPub    *tpm2.TPMTPublic // (optional) public key to use for transit encryption
}

type TPMSignerConfig struct {
	TPMConfig    TPMConfig
	AccessKeyID  string
	SessionToken string
}

type TPMSigner struct {
	refreshMutex     *sync.Mutex
	TPMConfig        TPMConfig
	AccessKeyID      string
	SessionToken     string
	encryptionHandle tpm2.TPMHandle
	encryptionPub    *tpm2.TPMTPublic
}

const (
	maxInputBuffer = 1024
)

var ()

func NewTPMSigner(cfg *TPMSignerConfig) (*TPMSigner, error) {

	if cfg.TPMConfig.TPMDevice == nil {
		return nil, fmt.Errorf("TpmDevice and TpmHandle must be specified")
	}
	return &TPMSigner{
		refreshMutex:     &sync.Mutex{},
		TPMConfig:        cfg.TPMConfig,
		AccessKeyID:      cfg.AccessKeyID,
		SessionToken:     cfg.SessionToken,
		encryptionHandle: cfg.TPMConfig.EncryptionHandle,
		encryptionPub:    cfg.TPMConfig.EncryptionPub,
	}, nil
}

func (ts *TPMSigner) MAC(msg []byte) ([]byte, error) {

	ts.refreshMutex.Lock()
	defer ts.refreshMutex.Unlock()

	rwr := transport.FromReadWriter(ts.TPMConfig.TPMDevice)
	return ts.hmac(rwr, msg, ts.TPMConfig.AuthHandle, ts.TPMConfig.Auth)
}

func (ts *TPMSigner) hmac(rwr transport.TPM, data []byte, objAuthHandle tpm2.AuthHandle, objAuth tpm2.TPM2BAuth) ([]byte, error) {

	hmacStart := tpm2.HmacStart{
		Handle:  objAuthHandle,
		Auth:    objAuth,
		HashAlg: tpm2.TPMAlgNull,
	}

	var rsess tpm2.Session
	if ts.encryptionHandle != 0 && ts.encryptionPub != nil {
		rsess = tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.Salted(ts.encryptionHandle, *ts.encryptionPub))
	} else {
		rsess = tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn))
	}

	rspHS, err := hmacStart.Execute(rwr, rsess)
	if err != nil {
		return nil, err
	}

	authHandle := tpm2.AuthHandle{
		Name:   objAuthHandle.Name,
		Handle: rspHS.SequenceHandle,
		Auth:   tpm2.PasswordAuth(objAuth.Buffer),
	}
	for len(data) > maxInputBuffer {
		sequenceUpdate := tpm2.SequenceUpdate{
			SequenceHandle: authHandle,
			Buffer: tpm2.TPM2BMaxBuffer{
				Buffer: data[:maxInputBuffer],
			},
		}
		_, err = sequenceUpdate.Execute(rwr)
		if err != nil {
			return nil, err
		}
		data = data[maxInputBuffer:]
	}

	sequenceComplete := tpm2.SequenceComplete{
		SequenceHandle: authHandle,
		Buffer: tpm2.TPM2BMaxBuffer{
			Buffer: data,
		},
		Hierarchy: tpm2.TPMRHOwner,
	}

	rspSC, err := sequenceComplete.Execute(rwr)
	if err != nil {
		return nil, err
	}

	return rspSC.Result.Buffer, nil

}
