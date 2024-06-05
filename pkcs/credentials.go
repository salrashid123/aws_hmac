package pkcs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/schema"
	hmacsigner "github.com/salrashid123/aws_hmac/pkcs/signer"
	hmacsignerv4 "github.com/salrashid123/aws_hmac/pkcs/signer/v4"
	stsschema "github.com/salrashid123/aws_hmac/stsschema"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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
	AssumeRoleInput      *sts.AssumeRoleInput
	PKCSSigner           *hmacsigner.PKCSSigner
	GetSessionTokenInput *sts.GetSessionTokenInput

	Version    string
	Region     string
	expiration time.Time
}

type PKCSCredentialsProvider struct {
	assumeRoleInput      *sts.AssumeRoleInput
	pkcsSigner           *hmacsigner.PKCSSigner
	getSessionTokenInput *sts.GetSessionTokenInput
	version              string
	region               string
	expiration           time.Time
}

func NewAWSPKCSCredentials(cfg PKCSProvider) (*PKCSCredentialsProvider, error) {

	if cfg.AssumeRoleInput == nil && cfg.GetSessionTokenInput == nil {
		return nil, errors.New("error either AssumeRoleInput or GetSessionTokenInput must be set")
	}
	if cfg.Region == "" {
		return nil, errors.New("error Region must be set")
	}
	if cfg.Version == "" {
		cfg.Version = defaultVersion
	}
	return &PKCSCredentialsProvider{
		assumeRoleInput:      cfg.AssumeRoleInput,
		pkcsSigner:           cfg.PKCSSigner,
		getSessionTokenInput: cfg.GetSessionTokenInput,
		version:              cfg.Version,
		region:               cfg.Region,
	}, nil

}

func (s *PKCSCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {

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

		err = hsa.SignHTTP(ctx, *s.pkcsSigner, sreq, postPayloadHash, "sts", s.region, time.Now())
		if err != nil {
			return aws.Credentials{}, err
		}

		sres, err := http.DefaultClient.Do(sreq)
		if err != nil {
			return aws.Credentials{}, err
		}

		defer sres.Body.Close()
		if sres.StatusCode != 200 {
			data, err := ioutil.ReadAll(sres.Body)
			if err != nil {
				return aws.Credentials{}, err
			}
			return aws.Credentials{}, fmt.Errorf("Error requesting credentials %s\n", data)
		}

		var stsOutput stsschema.AssumeRoleResponse

		data, err := ioutil.ReadAll(sres.Body)
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

		err = hsa.SignHTTP(ctx, *s.pkcsSigner, sreq, postPayloadHash, "sts", s.region, time.Now())
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
			Expires:         stsOutput.SessionTokenResult.Credentials.Expiration,
		}

		s.expiration = stsOutput.SessionTokenResult.Credentials.Expiration
	}

	if v.Source == "" {
		v.Source = PKCSProviderName
	}

	return v, nil
}

func (s *PKCSCredentialsProvider) IsExpired() bool {
	if time.Now().Add(time.Second * time.Duration(refreshTolerance)).After(s.expiration) {
		return true
	}
	return false
}

func (s *PKCSCredentialsProvider) ExpiresAt() time.Time {
	return s.expiration
}
