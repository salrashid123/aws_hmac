package signer

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type TPMConfig struct {
	TPMDevice        io.ReadWriteCloser // TPM ReadCloser
	NamedHandle      tpm2.NamedHandle   // tpm2NameHandle
	AuthSession      Session            // If the key needs a session, supply one as the `tpmjwt.Session`
	EncryptionHandle tpm2.TPMHandle     // (optional) handle to use for transit encryption
	EncryptionPub    *tpm2.TPMTPublic   // (optional) public key to use for transit encryption
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

	var se tpm2.Session
	if ts.TPMConfig.AuthSession != nil {
		var err error
		var closer func() error
		se, closer, err = ts.TPMConfig.AuthSession.GetSession()
		if err != nil {
			return nil, fmt.Errorf("aws_hmac: error getting session %v", err)
		}
		defer closer()
	} else {
		se = tpm2.PasswordAuth(nil)
	}

	objAuth := &tpm2.TPM2BAuth{}

	return ts.hmac(rwr, msg, ts.TPMConfig.NamedHandle, *objAuth, se)
}

func (ts *TPMSigner) hmac(rwr transport.TPM, data []byte, objNamedHandle tpm2.NamedHandle, objAuth tpm2.TPM2BAuth, sess tpm2.Session) ([]byte, error) {

	var rsess tpm2.Session
	if ts.encryptionHandle != 0 && ts.encryptionPub != nil {
		rsess = tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.Salted(ts.encryptionHandle, *ts.encryptionPub))
	} else {
		rsess = tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn))
	}
	rspHS, err := tpm2.HmacStart{
		Handle: tpm2.AuthHandle{
			Handle: objNamedHandle.Handle,
			Name:   objNamedHandle.Name,
			Auth:   sess,
		},
		Auth:    objAuth,
		HashAlg: tpm2.TPMAlgNull,
	}.Execute(rwr, rsess)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing HMAC sequenceStart  %v\n", err)
		return nil, err
	}

	authHandle := tpm2.AuthHandle{
		Name:   objNamedHandle.Name,
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
			fmt.Fprintf(os.Stderr, "Error executing HMAC sequenceUpdate  %v\n", err)
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
		fmt.Fprintf(os.Stderr, "Error executing HMAC sequenceComplete  %v\n", err)
		return nil, err
	}
	return rspSC.Result.Buffer, nil
}

type Session interface {
	GetSession() (auth tpm2.Session, closer func() error, err error) // this supplies the session handle to the library
}

// for pcr sessions
type PCRSession struct {
	rwr transport.TPM
	sel []tpm2.TPMSPCRSelection
}

func NewPCRSession(rwr transport.TPM, sel []tpm2.TPMSPCRSelection) (PCRSession, error) {
	return PCRSession{rwr, sel}, nil
}

func (p PCRSession) GetSession() (auth tpm2.Session, closer func() error, err error) {
	sess, closer, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}
	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: p.sel,
		},
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}
	return sess, closer, nil
}

// for password sessions
type PasswordSession struct {
	rwr      transport.TPM
	password []byte
}

func NewPasswordSession(rwr transport.TPM, password []byte) (PasswordSession, error) {
	return PasswordSession{rwr, password}, nil
}

func (p PasswordSession) GetSession() (auth tpm2.Session, closer func() error, err error) {
	c := func() error { return nil }
	return tpm2.PasswordAuth(p.password), c, nil
}
