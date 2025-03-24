package tpm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"

	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/gorilla/schema"

	"github.com/aws/aws-sdk-go-v2/service/sts"

	stsschema "github.com/salrashid123/aws_hmac/stsschema"
	hmacsigner "github.com/salrashid123/aws_hmac/tpm/signer"
	hmacsignerv4 "github.com/salrashid123/aws_hmac/tpm/signer/v4"
)

const (
	TPMProviderName  = "TPMProvider"
	refreshTolerance = 60
	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	defaultVersion   = "2011-06-15"
	stsEndpoint      = "https://sts.amazonaws.com"
)

var ()

type TPMProvider struct {
	AssumeRoleInput      *sts.AssumeRoleInput      // sts.AssumeRoleInput structure
	TPMSigner            *hmacsigner.TPMSigner     // TPMSigner from github.com/salrashid123/aws_hmac/tpm/signer
	GetSessionTokenInput *sts.GetSessionTokenInput // sts.SessionTokenInput structure
	Version              string                    // default: "2011-06-15",
	Region               string
}

type TPMCredentialsProvider struct {
	assumeRoleInput      *sts.AssumeRoleInput
	tpmSigner            *hmacsigner.TPMSigner
	getSessionTokenInput *sts.GetSessionTokenInput
	version              string
	region               string
	expiration           time.Time
}

// NewAWSTPMCredentials create AWS TPM based HMAC authentictaion credentials.
//
//	the root HMAC key is sealed inside a Trusted Platform Module (TPM)
func NewAWSTPMCredentials(cfg TPMProvider) (*TPMCredentialsProvider, error) {
	if cfg.AssumeRoleInput == nil && cfg.GetSessionTokenInput == nil {
		return &TPMCredentialsProvider{}, errors.New("error either AssumeRoleInput or GetSessionTokenInput must be set")
	}
	if cfg.Region == "" {
		return &TPMCredentialsProvider{}, errors.New("error Region must be set")
	}
	if cfg.Version == "" {
		cfg.Version = defaultVersion
	}

	return &TPMCredentialsProvider{
		assumeRoleInput:      cfg.AssumeRoleInput,
		tpmSigner:            cfg.TPMSigner,
		getSessionTokenInput: cfg.GetSessionTokenInput,
		version:              cfg.Version,
		region:               cfg.Region,
	}, nil
}

func (s *TPMCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {

	var v aws.Credentials
	if s.assumeRoleInput != nil {

		al := stsschema.AssumeRoleInput{
			Action:          "AssumeRole",
			Version:         defaultVersion,
			DurationSeconds: s.assumeRoleInput.DurationSeconds,
			RoleArn:         s.assumeRoleInput.RoleArn,
			RoleSessionName: s.assumeRoleInput.RoleSessionName,
		}

		form := url.Values{}

		err := schema.NewEncoder().Encode(al, form)
		if err != nil {
			return aws.Credentials{}, err
		}
		sreq, err := http.NewRequest(http.MethodPost, stsEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return aws.Credentials{}, err
		}
		sreq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		hasher := sha256.New()
		_, err = hasher.Write([]byte(form.Encode()))
		if err != nil {
			return aws.Credentials{}, err
		}
		postPayloadHash := hex.EncodeToString(hasher.Sum(nil))
		ctx := context.Background()
		hsa := hmacsignerv4.NewSigner()

		err = hsa.SignHTTP(ctx, *s.tpmSigner, sreq, postPayloadHash, "sts", s.region, time.Now())
		if err != nil {
			return aws.Credentials{}, err
		}

		sres, err := http.DefaultClient.Do(sreq)
		if err != nil {
			return aws.Credentials{}, err
		}

		defer sres.Body.Close()
		if sres.StatusCode != 200 {
			data, err := io.ReadAll(sres.Body)
			if err != nil {
				return aws.Credentials{}, err
			}
			return aws.Credentials{}, fmt.Errorf("error requesting credentials %s\n", data)
		}

		var stsOutput stsschema.AssumeRoleResponse

		data, err := io.ReadAll(sres.Body)
		if err != nil {
			return aws.Credentials{}, err
		}

		err = xml.Unmarshal(data, &stsOutput)
		if err != nil {
			return aws.Credentials{}, err
		}

		v = aws.Credentials{
			AccessKeyID:     stsOutput.AssumeRoleResult.Credentials.AccessKeyId,
			SecretAccessKey: stsOutput.AssumeRoleResult.Credentials.SecretAccessKey,
			SessionToken:    stsOutput.AssumeRoleResult.Credentials.SessionToken,
			Expires:         stsOutput.AssumeRoleResult.Credentials.Expiration,
		}

		s.expiration = stsOutput.AssumeRoleResult.Credentials.Expiration
	}

	if s.getSessionTokenInput != nil {

		sl := stsschema.GetSessionTokenInput{
			Action:          "GetSessionToken",
			Version:         defaultVersion,
			DurationSeconds: s.getSessionTokenInput.DurationSeconds,
		}

		form := url.Values{}

		err := schema.NewEncoder().Encode(sl, form)
		if err != nil {
			return aws.Credentials{}, err
		}
		sreq, err := http.NewRequest(http.MethodPost, stsEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return aws.Credentials{}, err
		}
		sreq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		hasher := sha256.New()
		_, err = hasher.Write([]byte(form.Encode()))
		if err != nil {
			return aws.Credentials{}, err
		}
		postPayloadHash := hex.EncodeToString(hasher.Sum(nil))
		ctx := context.Background()
		hsa := hmacsignerv4.NewSigner()

		err = hsa.SignHTTP(ctx, *s.tpmSigner, sreq, postPayloadHash, "sts", s.region, time.Now())
		if err != nil {
			return aws.Credentials{}, err
		}

		sres, err := http.DefaultClient.Do(sreq)
		if err != nil {
			return aws.Credentials{}, err
		}

		defer sres.Body.Close()
		if sres.StatusCode != 200 {
			data, err := io.ReadAll(sres.Body)
			if err != nil {
				return aws.Credentials{}, err
			}
			return aws.Credentials{}, fmt.Errorf("error requesting credentials %s\n", data)
		}

		var stsOutput stsschema.GetSessionTokenResponse

		data, err := io.ReadAll(sres.Body)
		if err != nil {
			return aws.Credentials{}, err
		}

		err = xml.Unmarshal(data, &stsOutput)
		if err != nil {
			return aws.Credentials{}, err
		}

		v = aws.Credentials{
			AccessKeyID:     stsOutput.SessionTokenResult.Credentials.AccessKeyId,
			SecretAccessKey: stsOutput.SessionTokenResult.Credentials.SecretAccessKey,
			SessionToken:    stsOutput.SessionTokenResult.Credentials.SessionToken,
			Expires:         stsOutput.SessionTokenResult.Credentials.Expiration,
		}

		s.expiration = stsOutput.SessionTokenResult.Credentials.Expiration
	}

	if v.Source == "" {
		v.Source = TPMProviderName
	}

	return v, nil
}

func (s *TPMCredentialsProvider) IsExpired() bool {
	if time.Now().Add(time.Second * time.Duration(refreshTolerance)).After(s.expiration) {
		return true
	}
	return false
}

func (s *TPMCredentialsProvider) ExpiresAt() time.Time {
	return s.expiration
}
