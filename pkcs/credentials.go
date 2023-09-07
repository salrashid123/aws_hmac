package pkcs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/schema"
	hmacsigner "github.com/salrashid123/aws_hmac/pkcs/signer"
	hmacsignerv4 "github.com/salrashid123/aws_hmac/pkcs/signer/v4"
	stsschema "github.com/salrashid123/aws_hmac/stsschema"

	creds "github.com/aws/aws-sdk-go/aws/credentials"
)

const (
	PKCSProviderName = "PKCSProvider"
	refreshTolerance = 60
	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	defaultVersion   = "2011-06-15"
	stsEndpoint      = "https://sts.amazonaws.com"
)

var ()

type PKCSProvider struct {
	AssumeRoleInput      *stsschema.AssumeRoleInput
	PKCSSigner           *hmacsigner.PKCSSigner
	GetSessionTokenInput *stsschema.GetSessionTokenInput
	Version              string
	Region               string
	expiration           time.Time
}

func NewAWSPKCSCredentials(cfg PKCSProvider) (*creds.Credentials, error) {
	if cfg.AssumeRoleInput == nil && cfg.GetSessionTokenInput == nil {
		return nil, errors.New("error either AssumeRoleInput or GetSessionTokenInput must be set")
	}
	if cfg.Region == "" {
		return nil, errors.New("error Region must be set")
	}
	if cfg.Version == "" {
		cfg.Version = defaultVersion
	}
	return creds.NewCredentials(&cfg), nil
}

func (s *PKCSProvider) Retrieve() (creds.Value, error) {

	var v creds.Value
	if s.AssumeRoleInput != nil {

		s.AssumeRoleInput.Action = "AssumeRole"
		s.AssumeRoleInput.Version = defaultVersion

		form := url.Values{}

		err := schema.NewEncoder().Encode(s, form)
		if err != nil {
			return creds.Value{}, err
		}
		sreq, err := http.NewRequest(http.MethodPost, stsEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return creds.Value{}, err
		}
		sreq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		hasher := sha256.New()
		_, err = hasher.Write([]byte(form.Encode()))
		if err != nil {
			return creds.Value{}, err
		}
		postPayloadHash := hex.EncodeToString(hasher.Sum(nil))
		ctx := context.Background()
		hsa := hmacsignerv4.NewSigner()

		err = hsa.SignHTTP(ctx, *s.PKCSSigner, sreq, postPayloadHash, "sts", s.Region, time.Now())
		if err != nil {
			return creds.Value{}, err
		}

		sres, err := http.DefaultClient.Do(sreq)
		if err != nil {
			return creds.Value{}, err
		}

		defer sres.Body.Close()
		if sres.StatusCode != 200 {
			data, err := ioutil.ReadAll(sres.Body)
			if err != nil {
				return creds.Value{}, err
			}
			return creds.Value{}, fmt.Errorf("Error requesting credentials %s\n", data)
		}

		var stsOutput stsschema.AssumeRoleResponse

		data, err := ioutil.ReadAll(sres.Body)
		if err != nil {
			return creds.Value{}, err
		}
		err = xml.Unmarshal(data, &stsOutput)
		if err != nil {
			return creds.Value{}, err
		}

		v = creds.Value{
			AccessKeyID:     stsOutput.AssumeRoleResult.Credentials.AccessKeyId,
			SecretAccessKey: stsOutput.AssumeRoleResult.Credentials.SecretAccessKey,
			SessionToken:    stsOutput.AssumeRoleResult.Credentials.SessionToken,
		}

		s.expiration = stsOutput.AssumeRoleResult.Credentials.Expiration
	}

	if s.GetSessionTokenInput != nil {

		s.GetSessionTokenInput.Action = "GetSessionToken"
		s.GetSessionTokenInput.Version = defaultVersion
		form := url.Values{}

		err := schema.NewEncoder().Encode(s, form)
		if err != nil {
			return creds.Value{}, err
		}
		sreq, err := http.NewRequest(http.MethodPost, stsEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return creds.Value{}, err
		}
		sreq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		hasher := sha256.New()
		_, err = hasher.Write([]byte(form.Encode()))
		if err != nil {
			return creds.Value{}, err
		}
		postPayloadHash := hex.EncodeToString(hasher.Sum(nil))
		ctx := context.Background()
		hsa := hmacsignerv4.NewSigner()

		err = hsa.SignHTTP(ctx, *s.PKCSSigner, sreq, postPayloadHash, "sts", s.Region, time.Now())
		if err != nil {
			return creds.Value{}, err
		}

		sres, err := http.DefaultClient.Do(sreq)
		if err != nil {
			return creds.Value{}, err
		}

		defer sres.Body.Close()
		if sres.StatusCode != 200 {
			data, err := ioutil.ReadAll(sres.Body)
			if err != nil {
				return creds.Value{}, err
			}
			return creds.Value{}, fmt.Errorf("Error requesting credentials %s\n", data)
		}

		var stsOutput stsschema.GetSessionTokenResponse

		data, err := ioutil.ReadAll(sres.Body)
		if err != nil {
			return creds.Value{}, err
		}
		err = xml.Unmarshal(data, &stsOutput)
		if err != nil {
			return creds.Value{}, err
		}

		v = creds.Value{
			AccessKeyID:     stsOutput.SessionTokenResult.Credentials.AccessKeyId,
			SecretAccessKey: stsOutput.SessionTokenResult.Credentials.SecretAccessKey,
			SessionToken:    stsOutput.SessionTokenResult.Credentials.SessionToken,
		}

		s.expiration = stsOutput.SessionTokenResult.Credentials.Expiration
	}

	if v.ProviderName == "" {
		v.ProviderName = PKCSProviderName
	}

	return v, nil
}

func (s *PKCSProvider) IsExpired() bool {
	if time.Now().Add(time.Second * time.Duration(refreshTolerance)).After(s.expiration) {
		return true
	}
	return false
}

func (s *PKCSProvider) ExpiresAt() time.Time {
	return s.expiration
}
