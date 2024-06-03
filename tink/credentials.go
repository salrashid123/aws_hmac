package tink

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
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/gorilla/schema"
	stsschema "github.com/salrashid123/aws_hmac/stsschema"
	hmacsigner "github.com/salrashid123/aws_hmac/tink/signer"
	hmacsignerv4 "github.com/salrashid123/aws_hmac/tink/signer/v4"
)

const (
	TINKProviderName = "TINKProvider"
	refreshTolerance = 60
	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	defaultVersion   = "2011-06-15"
	stsEndpoint      = "https://sts.amazonaws.com"
)

var ()

type TINKProvider struct {
	AssumeRoleInput      *sts.AssumeRoleInput
	TinkSigner           *hmacsigner.TinkSigner
	GetSessionTokenInput *sts.GetSessionTokenInput
	Version              string
	Region               string
	expiration           time.Time
}

type TinkCredentialsProvider struct {
	assumeRoleInput      *sts.AssumeRoleInput
	tinkSigner           *hmacsigner.TinkSigner
	getSessionTokenInput *sts.GetSessionTokenInput
	version              string
	region               string
	expiration           time.Time
}

func NewAWSTinkCredentials(cfg TINKProvider) (*TinkCredentialsProvider, error) {
	if cfg.AssumeRoleInput == nil && cfg.GetSessionTokenInput == nil {
		return nil, errors.New("error either AssumeRoleInput or GetSessionTokenInput must be set")
	}
	if cfg.Region == "" {
		return nil, errors.New("error Region must be set")
	}
	if cfg.Version == "" {
		cfg.Version = defaultVersion
	}
	return &TinkCredentialsProvider{
		assumeRoleInput:      cfg.AssumeRoleInput,
		tinkSigner:           cfg.TinkSigner,
		getSessionTokenInput: cfg.GetSessionTokenInput,
		version:              cfg.Version,
		region:               cfg.Region,
	}, nil

}

func (s *TinkCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {

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

		err = hsa.SignHTTP(ctx, *s.tinkSigner, sreq, postPayloadHash, "sts", s.region, time.Now())
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
			return aws.Credentials{}, fmt.Errorf("Error requesting credentials %s\n", data)
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

		err = hsa.SignHTTP(ctx, *s.tinkSigner, sreq, postPayloadHash, "sts", s.region, time.Now())
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
			return aws.Credentials{}, fmt.Errorf("Error requesting credentials %s\n", data)
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
		}

		s.expiration = stsOutput.SessionTokenResult.Credentials.Expiration
	}

	if v.Source == "" {
		v.Source = TINKProviderName
	}

	return v, nil
}

func (s *TinkCredentialsProvider) IsExpired() bool {
	if time.Now().Add(time.Second * time.Duration(refreshTolerance)).After(s.expiration) {
		return true
	}
	return false
}

func (s *TinkCredentialsProvider) ExpiresAt() time.Time {
	return s.expiration
}
