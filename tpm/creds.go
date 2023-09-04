// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package credentials

import (
	"bytes"
	"fmt"
	"io"
	"sync"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

type TPMConfig struct {
	TPMDevice io.ReadWriteCloser
	TpmHandle tpmutil.Handle
}

type HMACCredentialConfig struct {
	TPMConfig    TPMConfig
	AccessKeyID  string
	SessionToken string
}

type HMACCredential struct {
	refreshMutex *sync.Mutex
	TPMConfig    TPMConfig
	AccessKeyID  string
	SessionToken string
}

const (
	emptyPassword                 = ""
	CmdHmacStart  tpmutil.Command = 0x0000015B
)

var ()

func NewHMACCredential(cfg *HMACCredentialConfig) (*HMACCredential, error) {

	if cfg.TPMConfig.TPMDevice == nil { //|| cfg.TPMConfig.TpmHandle == nil {
		return nil, fmt.Errorf("TpmDevice and TpmHandle must be specified")
	}
	return &HMACCredential{
		refreshMutex: &sync.Mutex{},
		TPMConfig:    cfg.TPMConfig,
		AccessKeyID:  cfg.AccessKeyID,
		SessionToken: cfg.SessionToken,
	}, nil
}

func (ts *HMACCredential) MAC(msg []byte) ([]byte, error) {

	ts.refreshMutex.Lock()
	defer ts.refreshMutex.Unlock()

	newHandle := ts.TPMConfig.TpmHandle

	maxDigestBuffer := 1024
	seqAuth := ""
	seq, err := HmacStart(ts.TPMConfig.TPMDevice, seqAuth, newHandle, tpm2.AlgSHA256)
	if err != nil {
		return []byte(""), err
	}
	defer tpm2.FlushContext(ts.TPMConfig.TPMDevice, seq)

	plain := []byte(msg)
	for len(plain) > maxDigestBuffer {
		if err = tpm2.SequenceUpdate(ts.TPMConfig.TPMDevice, seqAuth, seq, plain[:maxDigestBuffer]); err != nil {
			return []byte(""), err
		}
		plain = plain[maxDigestBuffer:]
	}

	digest, _, err := tpm2.SequenceComplete(ts.TPMConfig.TPMDevice, seqAuth, seq, tpm2.HandleNull, plain)
	if err != nil {
		return []byte(""), err
	}

	return digest, nil

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
