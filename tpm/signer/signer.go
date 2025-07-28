package signer

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type TPMConfig struct {
	TPMDevice        io.ReadWriteCloser // TPM ReadCloser
	Handle           tpm2.TPMHandle     // TPMHandle for the hmac key
	AuthSession      Session            // If the key needs a session, supply one as the `tpmjwt.Session`
	EncryptionHandle tpm2.TPMHandle     // (optional) handle to use for transit encryption
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
	pss := make([]byte, 32)
	_, err := rand.Read(pss)
	if err != nil {
		return nil, fmt.Errorf("tpmjwt: failed to generate random for hash %v", err)
	}

	objAuth := &tpm2.TPM2BAuth{
		Buffer: pss,
	}

	pub, err := tpm2.ReadPublic{
		ObjectHandle: ts.TPMConfig.Handle,
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("aws_hmac: error getting public %v", err)
	}

	nh := tpm2.NamedHandle{
		Handle: ts.TPMConfig.Handle,
		Name:   pub.Name,
	}
	return ts.hmac(rwr, msg, nh, *objAuth, se)
}

func (ts *TPMSigner) hmac(rwr transport.TPM, data []byte, objNamedHandle tpm2.NamedHandle, objAuth tpm2.TPM2BAuth, sess tpm2.Session) ([]byte, error) {

	var rsess tpm2.Session
	if ts.encryptionHandle != 0 {
		encryptionPub, err := tpm2.ReadPublic{
			ObjectHandle: ts.encryptionHandle,
		}.Execute(rwr)
		if err != nil {
			return nil, err
		}
		ePubName, err := encryptionPub.OutPublic.Contents()
		if err != nil {
			return nil, err
		}
		rsess = tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.Salted(ts.encryptionHandle, *ePubName))
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

type PolicyAuthValueDuplicateSelectSession struct {
	rwr      transport.TPM
	password []byte
	ekName   tpm2.TPM2BName
	_        Session
}

func NewPolicyAuthValueAndDuplicateSelectSession(rwr transport.TPM, password []byte, ekName tpm2.TPM2BName) (PolicyAuthValueDuplicateSelectSession, error) {
	return PolicyAuthValueDuplicateSelectSession{rwr, password, ekName, nil}, nil
}

func (p PolicyAuthValueDuplicateSelectSession) GetSession() (auth tpm2.Session, closer func() error, err error) {

	pa_sess, pa_cleanup, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}
	//defer pa_cleanup()

	_, err = tpm2.PolicyAuthValue{
		PolicySession: pa_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	papgd, err := tpm2.PolicyGetDigest{
		PolicySession: pa_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}
	err = pa_cleanup()
	if err != nil {
		return nil, nil, err
	}
	// as the "new parent"
	dupselect_sess, dupselect_cleanup, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}
	//defer dupselect_cleanup()

	_, err = tpm2.PolicyDuplicationSelect{
		PolicySession: dupselect_sess.Handle(),
		NewParentName: tpm2.TPM2BName(p.ekName),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	// calculate the digest
	dupselpgd, err := tpm2.PolicyGetDigest{
		PolicySession: dupselect_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}
	err = dupselect_cleanup()
	if err != nil {
		return nil, nil, err
	}
	// now create an OR session with the two above policies above
	or_sess, or_cleanup, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(p.password))}...)
	if err != nil {
		return nil, nil, err
	}
	//defer or_cleanup()

	_, err = tpm2.PolicyAuthValue{
		PolicySession: or_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}
	_, err = tpm2.PolicyOr{
		PolicySession: or_sess.Handle(),
		PHashList:     tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{papgd.PolicyDigest, dupselpgd.PolicyDigest}},
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	return or_sess, or_cleanup, nil
}

type PCRAndDuplicateSelectSession struct {
	rwr      transport.TPM
	sel      []tpm2.TPMSPCRSelection
	password []byte
	ekName   tpm2.TPM2BName
	_        Session
}

func NewPCRAndDuplicateSelectSession(rwr transport.TPM, sel []tpm2.TPMSPCRSelection, password []byte, ekName tpm2.TPM2BName) (PCRAndDuplicateSelectSession, error) {
	return PCRAndDuplicateSelectSession{rwr, sel, password, ekName, nil}, nil
}

func (p PCRAndDuplicateSelectSession) GetSession() (auth tpm2.Session, closer func() error, err error) {

	// var options []tpm2.AuthOption
	// options = append(options, tpm2.Auth(p.password))

	pcr_sess, pcr_cleanup, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}

	_, err = tpm2.PolicyPCR{
		PolicySession: pcr_sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: p.sel,
		},
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	pcrpgd, err := tpm2.PolicyGetDigest{
		PolicySession: pcr_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}
	err = pcr_cleanup()
	if err != nil {
		return nil, nil, err
	}

	// create another real session with the PolicyDuplicationSelect and remember to specify the EK
	// as the "new parent"
	dupselect_sess, dupselect_cleanup, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}

	_, err = tpm2.PolicyDuplicationSelect{
		PolicySession: dupselect_sess.Handle(),
		NewParentName: p.ekName,
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	// calculate the digest
	dupselpgd, err := tpm2.PolicyGetDigest{
		PolicySession: dupselect_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}
	err = dupselect_cleanup()
	if err != nil {
		return nil, nil, err
	}

	// now create an OR session with the two above policies above
	or_sess, or_cleanup, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}
	//defer or_cleanup()

	_, err = tpm2.PolicyPCR{
		PolicySession: or_sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: p.sel,
		},
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	_, err = tpm2.PolicyOr{
		PolicySession: or_sess.Handle(),
		PHashList:     tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{pcrpgd.PolicyDigest, dupselpgd.PolicyDigest}},
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	return or_sess, or_cleanup, nil
}
