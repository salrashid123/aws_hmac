// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package credentials

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/tink"
	"github.com/hashicorp/vault/api"
	"github.com/miekg/pkcs11"
)

type VaultConfig struct {
	VaultToken  string
	VaultPath   string
	VaultCAcert string
	VaultAddr   string
}

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
	TPMConfig    TPMConfig
	VaultConfig  VaultConfig
	AccessKeyID  string
	SessionToken string
}

type TPMConfig struct {
	TpmHandleFile string
	TpmHandle     uint32
	TpmDevice     string
}

type HMACCredential struct {
	refreshMutex *sync.Mutex
	TinkConfig   TinkConfig
	PKCSConfig   PKCSConfig
	TPMConfig    TPMConfig
	VaultConfig  VaultConfig
	AccessKeyID  string
	SessionToken string
}

const (
	emptyPassword                 = ""
	CmdHmacStart  tpmutil.Command = 0x0000015B
)

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
		if cfg.TPMConfig.TpmDevice != "" {
			rwc, err := tpm2.OpenTPM(cfg.TPMConfig.TpmDevice)
			if err != nil {
				return &HMACCredential{}, err
			}

			if err := rwc.Close(); err != nil {
				return &HMACCredential{}, err
			}

		}
	}

	return &HMACCredential{
		refreshMutex: &sync.Mutex{},
		TinkConfig:   cfg.TinkConfig,
		TPMConfig:    cfg.TPMConfig,
		PKCSConfig:   cfg.PKCSConfig,
		VaultConfig:  cfg.VaultConfig,
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

	if ts.TPMConfig.TpmDevice != "" {

		rwc, err := tpm2.OpenTPM(ts.TPMConfig.TpmDevice)
		if err != nil {
			return []byte(""), err
		}
		defer func() {
			if err := rwc.Close(); err != nil {
				panic(err)
			}
		}()

		ekhBytes, err := ioutil.ReadFile(ts.TPMConfig.TpmHandleFile)
		if err != nil {
			return []byte(""), err
		}
		newHandle, err := tpm2.ContextLoad(rwc, ekhBytes)
		if err != nil {
			return []byte(""), err
		}

		maxDigestBuffer := 1024
		seqAuth := ""
		seq, err := HmacStart(rwc, seqAuth, newHandle, tpm2.AlgSHA256)
		if err != nil {
			return []byte(""), err
		}
		defer tpm2.FlushContext(rwc, seq)

		plain := []byte(msg)
		for len(plain) > maxDigestBuffer {
			if err = tpm2.SequenceUpdate(rwc, seqAuth, seq, plain[:maxDigestBuffer]); err != nil {
				return []byte(""), err
			}
			plain = plain[maxDigestBuffer:]
		}

		digest, _, err := tpm2.SequenceComplete(rwc, seqAuth, seq, tpm2.HandleNull, plain)
		if err != nil {
			return []byte(""), err
		}

		return digest, nil

	}

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

//  ***********************************************************************
// modified from from go-tpm/tpm2/tpm2.go
// 	CmdHmacStart                  tpmutil.Command = 0x0000015B

func encodeAuthArea(sections ...tpm2.AuthCommand) ([]byte, error) {
	var res tpmutil.RawBytes
	for _, s := range sections {
		buf, err := tpmutil.Pack(s)
		if err != nil {
			return nil, err
		}
		res = append(res, buf...)
	}

	size, err := tpmutil.Pack(uint32(len(res)))
	if err != nil {
		return nil, err
	}

	return concat(size, res)
}

func HmacStart(rw io.ReadWriter, sequenceAuth string, handle tpmutil.Handle, hashAlg tpm2.Algorithm) (seqHandle tpmutil.Handle, err error) {

	auth, err := encodeAuthArea(tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession, Auth: []byte(sequenceAuth)})
	if err != nil {
		return 0, err
	}
	out, err := tpmutil.Pack(handle)
	if err != nil {
		return 0, err
	}
	Cmd, err := concat(out, auth)
	if err != nil {
		return 0, err
	}

	resp, err := runCommand(rw, tpm2.TagSessions, CmdHmacStart, tpmutil.RawBytes(Cmd), tpmutil.U16Bytes(sequenceAuth), hashAlg)
	if err != nil {
		return 0, err
	}
	var rhandle tpmutil.Handle
	_, err = tpmutil.Unpack(resp, &rhandle)
	return rhandle, err
}

func runCommand(rw io.ReadWriter, tag tpmutil.Tag, Cmd tpmutil.Command, in ...interface{}) ([]byte, error) {
	resp, code, err := tpmutil.RunCommand(rw, tag, Cmd, in...)
	if err != nil {
		return nil, err
	}
	if code != tpmutil.RCSuccess {
		return nil, decodeResponse(code)
	}
	return resp, decodeResponse(code)
}

func concat(chunks ...[]byte) ([]byte, error) {
	return bytes.Join(chunks, nil), nil
}

func decodeResponse(code tpmutil.ResponseCode) error {
	if code == tpmutil.RCSuccess {
		return nil
	}
	if code&0x180 == 0 { // Bits 7:8 == 0 is a TPM1 error
		return fmt.Errorf("response status 0x%x", code)
	}
	if code&0x80 == 0 { // Bit 7 unset
		if code&0x400 > 0 { // Bit 10 set, vendor specific code
			return tpm2.VendorError{uint32(code)}
		}
		if code&0x800 > 0 { // Bit 11 set, warning with code in bit 0:6
			return tpm2.Warning{tpm2.RCWarn(code & 0x7f)}
		}
		// error with code in bit 0:6
		return tpm2.Error{tpm2.RCFmt0(code & 0x7f)}
	}
	if code&0x40 > 0 { // Bit 6 set, code in 0:5, parameter number in 8:11
		return tpm2.ParameterError{tpm2.RCFmt1(code & 0x3f), tpm2.RCIndex((code & 0xf00) >> 8)}
	}
	if code&0x800 == 0 { // Bit 11 unset, code in 0:5, handle in 8:10
		return tpm2.HandleError{tpm2.RCFmt1(code & 0x3f), tpm2.RCIndex((code & 0x700) >> 8)}
	}
	// Code in 0:5, Session in 8:10
	return tpm2.SessionError{tpm2.RCFmt1(code & 0x3f), tpm2.RCIndex((code & 0x700) >> 8)}
}
