package stsschema

import "time"

// https://docs.aws.amazon.com/sdk-for-go/api/service/sts/#STS.GetCallerIdentityRequest
type GetCallerIdentityRequest struct {
	Action  string `schema:"Action"`
	Version string `schema:"Version"`
}

type GetCallerIdentityResponse struct {
	CallerIdentityResult CallerIdentityResult `xml:"GetCallerIdentityResult"`
	ResponseMetadata     struct {
		RequestID string `xml:"RequestId,omitempty"`
	} `xml:"ResponseMetadata,omitempty"`
}

type CallerIdentityResult struct {
	Arn     string `xml:"Arn"`
	UserId  string `xml:"UserId"`
	Account int64  `xml:"Account"`
}

// https://docs.aws.amazon.com/sdk-for-go/api/service/sts/#GetSessionTokenInput
type GetSessionTokenInput struct {
	Action          string  `schema:"Action"`
	Version         string  `schema:"Version"`
	DurationSeconds *int32  `schema:"DurationSeconds,omitempty" min:"900" type:"integer"`
	SerialNumber    *string `schema:"SerialNumber,omitempty" min:"9" type:"string"`
	TokenCode       *string `schema:"TokenCode,omitempty" min:"6" type:"string"`
	// cant use 	sts.GetSessionTokenInput because i can't omit nulls
}

type GetSessionTokenResponse struct {
	SessionTokenResult SessionTokenResult `xml:"GetSessionTokenResult"`
	ResponseMetadata   struct {
		RequestID string `xml:"RequestId,omitempty"`
	} `xml:"ResponseMetadata,omitempty"`
}

type SessionTokenResult struct {
	Credentials Credentials `xml:"Credentials,omitempty"`
}

type SessionTokenResponse struct {
	IdentityType string `xml:"IdentityType"`
	AccountId    string `xml:"AccountId"`
	RequestId    string `xml:"RequestId"`
	PrincipalId  string `xml:"PrincipalId"`
	UserId       string `xml:"UserId"`
	Arn          string `xml:"Arn"`
	RoleId       string `xml:"RoleId"`
}

// https://docs.aws.amazon.com/sdk-for-go/api/service/sts/#AssumeRoleInput
type PolicyDescriptorType struct {
	Arn *string `schema:"PolicyDescriptorType,omitempty" locationName:"arn" min:"20" type:"string"`
}

type ProvidedContext struct {
	ContextAssertion *string `schema:"ContextAssertion,omitempty" min:"4" type:"string"`
	ProviderArn      *string `schema:"ProviderArn,omitempty" min:"20" type:"string"`
}

type Tag struct {
	Key   *string `schema:"Key,omitempty" min:"1" type:"string" required:"true"`
	Value *string `schema:"Value,omitempty" type:"string" required:"true"`
}

type AssumeRoleInput struct {
	Action            string                  `schema:"Action"`
	Version           string                  `schema:"Version"`
	DurationSeconds   *int32                  `schema:"DurationSeconds,omitempty" min:"900" type:"integer"`
	ExternalId        *string                 `schema:"ExternalId,omitempty" min:"2" type:"string"`
	Policy            *string                 `schema:"Policy,omitempty" min:"1" type:"string"`
	PolicyArns        []*PolicyDescriptorType `schema:"PolicyArns,omitempty" type:"list"`
	ProvidedContexts  []*ProvidedContext      `schema:"ProvidedContexts,omitempty" type:"list"`
	RoleArn           *string                 `schema:"RoleArn,omitempty" min:"20" type:"string" required:"true"`
	RoleSessionName   *string                 `schema:"RoleSessionName,omitempty" min:"2" type:"string" required:"true"`
	SerialNumber      *string                 `schema:"SerialNumber,omitempty" min:"9" type:"string"`
	SourceIdentity    *string                 `schema:"SourceIdentity,omitempty" min:"2" type:"string"`
	Tags              []*Tag                  `schema:"Tags,omitempty" type:"list"`
	TokenCode         *string                 `schema:"TokenCode,omitempty" min:"6" type:"string"`
	TransitiveTagKeys []*string               `schema:"TransitiveTagKeys,omitempty" type:"list"`
}

type AssumeRoleResponse struct {
	AssumeRoleResult AssumeRoleResult `xml:"AssumeRoleResult"`
	ResponseMetadata struct {
		RequestID string `xml:"RequestId,omitempty"`
	} `xml:"ResponseMetadata,omitempty"`
}

type AssumeRoleResult struct {
	AssumedRoleUser  AssumedRoleUser `xml:"AssumeRoleUser"`
	Credentials      Credentials     `xml:"Credentials,omitempty"`
	PackedPolicySize int             `xml:"PackedPolicySize,omitempty"`
	SourceIdentity   string          `xml:"SourceIdentity,omitempty"`
}

type AssumedRoleUser struct {
	Arn           string `xml:"Arn"`
	AssumedRoleID string `xml:"AssumeRoleId"`
}

// common

type Credentials struct {
	AccessKeyId     string    `xml:"AccessKeyId,omitempty"`
	SecretAccessKey string    `xml:"SecretAccessKey,omitempty"`
	Expiration      time.Time `xml:"Expiration,omitempty"`
	SessionToken    string    `xml:"SessionToken,omitempty"`
}
