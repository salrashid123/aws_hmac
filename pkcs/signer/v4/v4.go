// Attribution: https://github.com/aws/aws-sdk-go-v2/blob/main/aws/signer/v4/v4.go
package v4

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"net/http"
	"net/textproto"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/smithy-go/encoding/httpbinding"
	"github.com/aws/smithy-go/logging"
	hmaccred "github.com/salrashid123/aws_hmac/pkcs/signer"
)

const (
	signingAlgorithm    = "AWS4-HMAC-SHA256"
	authorizationHeader = "Authorization"
)

// HTTPSigner is an interface to a SigV4 signer that can sign HTTP requests
type HTTPSigner interface {
	//	SignHTTP(ctx context.Context, credentials aws.Credentials, r *http.Request, payloadHash string, service string, region string, signingTime time.Time, optFns ...func(*SignerOptions)) error
	SignHTTP(ctx context.Context, credentials hmaccred.PKCSSigner, r *http.Request, payloadHash string, service string, region string, signingTime time.Time, optFns ...func(*SignerOptions)) error
}

type keyDerivator interface {
	DeriveKey(credential hmaccred.PKCSSigner, service, region string, signingTime SigningTime) ([]byte, error)
}

// SignerOptions is the SigV4 Signer options.
type SignerOptions struct {
	// Disables the Signer's moving HTTP header key/value pairs from the HTTP
	// request header to the request's query string. This is most commonly used
	// with pre-signed requests preventing headers from being added to the
	// request's query string.
	DisableHeaderHoisting bool

	// Disables the automatic escaping of the URI path of the request for the
	// siganture's canonical string's path. For services that do not need additional
	// escaping then use this to disable the signer escaping the path.
	//
	// S3 is an example of a service that does not need additional escaping.
	//
	// http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
	DisableURIPathEscaping bool

	// The logger to send log messages to.
	Logger logging.Logger

	// Enable logging of signed requests.
	// This will enable logging of the canonical request, the string to sign, and for presigning the subsequent
	// presigned URL.
	LogSigning bool
}

// Signer applies AWS v4 signing to given request. Use this to sign requests
// that need to be signed with AWS V4 Signatures.
type Signer struct {
	options      SignerOptions
	keyDerivator keyDerivator
}

// NewSigner returns a new SigV4 Signer
func NewSigner(optFns ...func(signer *SignerOptions)) *Signer {
	options := SignerOptions{}

	for _, fn := range optFns {
		fn(&options)
	}

	return &Signer{options: options, keyDerivator: NewSigningKeyDeriver()}
}

type httpSigner struct {
	Request      *http.Request
	ServiceName  string
	Region       string
	Time         SigningTime
	Credentials  hmaccred.PKCSSigner
	KeyDerivator keyDerivator
	IsPreSign    bool

	PayloadHash string

	DisableHeaderHoisting  bool
	DisableURIPathEscaping bool
}

func (s *httpSigner) Build() (signedRequest, error) {
	req := s.Request

	query := req.URL.Query()
	headers := req.Header

	s.setRequiredSigningFields(headers, query)

	// Sort Each Query Key's Values
	for key := range query {
		sort.Strings(query[key])
	}

	SanitizeHostForHeader(req)

	credentialScope := s.buildCredentialScope()
	credentialStr := s.Credentials.AccessKeyID + "/" + credentialScope
	if s.IsPreSign {
		query.Set(AmzCredentialKey, credentialStr)
	}

	unsignedHeaders := headers
	if s.IsPreSign && !s.DisableHeaderHoisting {
		var urlValues url.Values
		urlValues, unsignedHeaders = buildQuery(AllowedQueryHoisting, headers)
		for k := range urlValues {
			query[k] = urlValues[k]
		}
	}

	host := req.URL.Host
	if len(req.Host) > 0 {
		host = req.Host
	}

	signedHeaders, signedHeadersStr, canonicalHeaderStr := s.buildCanonicalHeaders(host, IgnoredHeaders, unsignedHeaders, s.Request.ContentLength)

	if s.IsPreSign {
		query.Set(AmzSignedHeadersKey, signedHeadersStr)
	}

	var rawQuery strings.Builder
	rawQuery.WriteString(strings.Replace(query.Encode(), "+", "%20", -1))

	canonicalURI := GetURIPath(req.URL)
	if !s.DisableURIPathEscaping {
		canonicalURI = httpbinding.EscapePath(canonicalURI, false)
	}

	canonicalString := s.buildCanonicalString(
		req.Method,
		canonicalURI,
		rawQuery.String(),
		signedHeadersStr,
		canonicalHeaderStr,
	)

	strToSign := s.buildStringToSign(credentialScope, canonicalString)
	signingSignature, err := s.buildSignature(strToSign)
	if err != nil {
		return signedRequest{}, err
	}

	if s.IsPreSign {
		rawQuery.WriteString("&X-Amz-Signature=")
		rawQuery.WriteString(signingSignature)
	} else {
		headers[authorizationHeader] = append(headers[authorizationHeader][:0], buildAuthorizationHeader(credentialStr, signedHeadersStr, signingSignature))
	}

	req.URL.RawQuery = rawQuery.String()

	return signedRequest{
		Request:         req,
		SignedHeaders:   signedHeaders,
		CanonicalString: canonicalString,
		StringToSign:    strToSign,
		PreSigned:       s.IsPreSign,
	}, nil
}

func buildAuthorizationHeader(credentialStr, signedHeadersStr, signingSignature string) string {
	const credential = "Credential="
	const signedHeaders = "SignedHeaders="
	const signature = "Signature="
	const commaSpace = ", "

	var parts strings.Builder
	parts.Grow(len(signingAlgorithm) + 1 +
		len(credential) + len(credentialStr) + 2 +
		len(signedHeaders) + len(signedHeadersStr) + 2 +
		len(signature) + len(signingSignature),
	)
	parts.WriteString(signingAlgorithm)
	parts.WriteRune(' ')
	parts.WriteString(credential)
	parts.WriteString(credentialStr)
	parts.WriteString(commaSpace)
	parts.WriteString(signedHeaders)
	parts.WriteString(signedHeadersStr)
	parts.WriteString(commaSpace)
	parts.WriteString(signature)
	parts.WriteString(signingSignature)
	return parts.String()
}

// SignHTTP signs AWS v4 requests with the provided payload hash, service name, region the
// request is made to, and time the request is signed at. The signTime allows
// you to specify that a request is signed for the future, and cannot be
// used until then.
//
// The payloadHash is the hex encoded SHA-256 hash of the request payload, and
// must be provided. Even if the request has no payload (aka body). If the
// request has no payload you should use the hex encoded SHA-256 of an empty
// string as the payloadHash value.
//
//	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
//
// Some services such as Amazon S3 accept alternative values for the payload
// hash, such as "UNSIGNED-PAYLOAD" for requests where the body will not be
// included in the request signature.
//
// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
//
// Sign differs from Presign in that it will sign the request using HTTP
// header values. This type of signing is intended for http.Request values that
// will not be shared, or are shared in a way the header values on the request
// will not be lost.
//
// The passed in request will be modified in place.
// func (s Signer) SignHTTP(ctx context.Context, credentials aws.Credentials, r *http.Request, payloadHash string, service string, region string, signingTime time.Time, optFns ...func(options *SignerOptions)) error {
func (s Signer) SignHTTP(ctx context.Context, credentials hmaccred.PKCSSigner, r *http.Request, payloadHash string, service string, region string, signingTime time.Time, optFns ...func(options *SignerOptions)) error {
	options := s.options

	for _, fn := range optFns {
		fn(&options)
	}

	signer := &httpSigner{
		Request:                r,
		PayloadHash:            payloadHash,
		ServiceName:            service,
		Region:                 region,
		Credentials:            credentials,
		Time:                   NewSigningTime(signingTime.UTC()),
		DisableHeaderHoisting:  options.DisableHeaderHoisting,
		DisableURIPathEscaping: options.DisableURIPathEscaping,
		KeyDerivator:           s.keyDerivator,
	}

	signedRequest, err := signer.Build()
	if err != nil {
		return err
	}

	logSigningInfo(ctx, options, &signedRequest, false)

	return nil
}

// PresignHTTP signs AWS v4 requests with the payload hash, service name, region
// the request is made to, and time the request is signed at. The signTime
// allows you to specify that a request is signed for the future, and cannot
// be used until then.
//
// Returns the signed URL and the map of HTTP headers that were included in the
// signature or an error if signing the request failed. For presigned requests
// these headers and their values must be included on the HTTP request when it
// is made. This is helpful to know what header values need to be shared with
// the party the presigned request will be distributed to.
//
// The payloadHash is the hex encoded SHA-256 hash of the request payload, and
// must be provided. Even if the request has no payload (aka body). If the
// request has no payload you should use the hex encoded SHA-256 of an empty
// string as the payloadHash value.
//
//	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
//
// Some services such as Amazon S3 accept alternative values for the payload
// hash, such as "UNSIGNED-PAYLOAD" for requests where the body will not be
// included in the request signature.
//
// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
//
// PresignHTTP differs from SignHTTP in that it will sign the request using
// query string instead of header values. This allows you to share the
// Presigned Request's URL with third parties, or distribute it throughout your
// system with minimal dependencies.
//
// PresignHTTP will not set the expires time of the presigned request
// automatically. To specify the expire duration for a request add the
// "X-Amz-Expires" query parameter on the request with the value as the
// duration in seconds the presigned URL should be considered valid for. This
// parameter is not used by all AWS services, and is most notable used by
// Amazon S3 APIs.
//
//	expires := 20 * time.Minute
//	query := req.URL.Query()
//	query.Set("X-Amz-Expires", strconv.FormatInt(int64(expires/time.Second), 10)
//	req.URL.RawQuery = query.Encode()
//
// This method does not modify the provided request.
func (s *Signer) PresignHTTP(
	ctx context.Context, credentials hmaccred.PKCSSigner, r *http.Request,
	payloadHash string, service string, region string, signingTime time.Time,
	optFns ...func(*SignerOptions),
) (signedURI string, signedHeaders http.Header, err error) {
	options := s.options

	for _, fn := range optFns {
		fn(&options)
	}

	signer := &httpSigner{
		Request:                r.Clone(r.Context()),
		PayloadHash:            payloadHash,
		ServiceName:            service,
		Region:                 region,
		Credentials:            credentials,
		Time:                   NewSigningTime(signingTime.UTC()),
		IsPreSign:              true,
		DisableHeaderHoisting:  options.DisableHeaderHoisting,
		DisableURIPathEscaping: options.DisableURIPathEscaping,
		KeyDerivator:           s.keyDerivator,
	}

	signedRequest, err := signer.Build()
	if err != nil {
		return "", nil, err
	}

	logSigningInfo(ctx, options, &signedRequest, true)

	signedHeaders = make(http.Header)

	// For the signed headers we canonicalize the header keys in the returned map.
	// This avoids situations where can standard library double headers like host header. For example the standard
	// library will set the Host header, even if it is present in lower-case form.
	for k, v := range signedRequest.SignedHeaders {
		key := textproto.CanonicalMIMEHeaderKey(k)
		signedHeaders[key] = append(signedHeaders[key], v...)
	}

	return signedRequest.Request.URL.String(), signedHeaders, nil
}

func (s *httpSigner) buildCredentialScope() string {
	return strings.Join([]string{
		s.Time.ShortTimeFormat(),
		s.Region,
		s.ServiceName,
		"aws4_request",
	}, "/")
}

func buildQuery(r Rule, header http.Header) (url.Values, http.Header) {
	query := url.Values{}
	unsignedHeaders := http.Header{}
	for k, h := range header {
		if r.IsValid(k) {
			query[k] = h
		} else {
			unsignedHeaders[k] = h
		}
	}

	return query, unsignedHeaders
}

func (s *httpSigner) buildCanonicalHeaders(host string, rule Rule, header http.Header, length int64) (signed http.Header, signedHeaders, canonicalHeadersStr string) {
	signed = make(http.Header)

	var headers []string
	const hostHeader = "host"
	headers = append(headers, hostHeader)
	signed[hostHeader] = append(signed[hostHeader], host)

	if length > 0 {
		const contentLengthHeader = "content-length"
		headers = append(headers, contentLengthHeader)
		signed[contentLengthHeader] = append(signed[contentLengthHeader], strconv.FormatInt(length, 10))
	}

	for k, v := range header {
		if !rule.IsValid(k) {
			continue // ignored header
		}

		lowerCaseKey := strings.ToLower(k)
		if _, ok := signed[lowerCaseKey]; ok {
			// include additional values
			signed[lowerCaseKey] = append(signed[lowerCaseKey], v...)
			continue
		}

		headers = append(headers, lowerCaseKey)
		signed[lowerCaseKey] = v
	}
	sort.Strings(headers)

	signedHeaders = strings.Join(headers, ";")

	var canonicalHeaders strings.Builder
	n := len(headers)
	const colon = ':'
	for i := 0; i < n; i++ {
		if headers[i] == hostHeader {
			canonicalHeaders.WriteString(hostHeader)
			canonicalHeaders.WriteRune(colon)
			canonicalHeaders.WriteString(StripExcessSpaces(host))
		} else {
			canonicalHeaders.WriteString(headers[i])
			canonicalHeaders.WriteRune(colon)
			canonicalHeaders.WriteString(strings.Join(signed[headers[i]], ","))
		}
		canonicalHeaders.WriteRune('\n')
	}
	canonicalHeadersStr = canonicalHeaders.String()

	return signed, signedHeaders, canonicalHeadersStr
}

func (s *httpSigner) buildCanonicalString(method, uri, query, signedHeaders, canonicalHeaders string) string {
	return strings.Join([]string{
		method,
		uri,
		query,
		canonicalHeaders,
		signedHeaders,
		s.PayloadHash,
	}, "\n")
}

func (s *httpSigner) buildStringToSign(credentialScope, canonicalRequestString string) string {
	return strings.Join([]string{
		signingAlgorithm,
		s.Time.TimeFormat(),
		credentialScope,
		hex.EncodeToString(makeHash(sha256.New(), []byte(canonicalRequestString))),
	}, "\n")
}

func makeHash(hash hash.Hash, b []byte) []byte {
	hash.Reset()
	hash.Write(b)
	return hash.Sum(nil)
}

func (s *httpSigner) buildSignature(strToSign string) (string, error) {
	key, err := s.KeyDerivator.DeriveKey(s.Credentials, s.ServiceName, s.Region, s.Time)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(HMACSHA256(key, []byte(strToSign))), nil
}

func (s *httpSigner) setRequiredSigningFields(headers http.Header, query url.Values) {
	amzDate := s.Time.TimeFormat()

	if s.IsPreSign {
		query.Set(AmzAlgorithmKey, signingAlgorithm)
		if sessionToken := s.Credentials.SessionToken; len(sessionToken) > 0 {
			query.Set("X-Amz-Security-Token", sessionToken)
		}

		query.Set(AmzDateKey, amzDate)
		return
	}

	headers[AmzDateKey] = append(headers[AmzDateKey][:0], amzDate)

	if len(s.Credentials.SessionToken) > 0 {
		headers[AmzSecurityTokenKey] = append(headers[AmzSecurityTokenKey][:0], s.Credentials.SessionToken)
	}
}

func logSigningInfo(ctx context.Context, options SignerOptions, request *signedRequest, isPresign bool) {
	if !options.LogSigning {
		return
	}
	signedURLMsg := ""
	if isPresign {
		signedURLMsg = fmt.Sprintf(logSignedURLMsg, request.Request.URL.String())
	}
	logger := logging.WithContext(ctx, options.Logger)
	logger.Logf(logging.Debug, logSignInfoMsg, request.CanonicalString, request.StringToSign, signedURLMsg)
}

type signedRequest struct {
	Request         *http.Request
	SignedHeaders   http.Header
	CanonicalString string
	StringToSign    string
	PreSigned       bool
}

const logSignInfoMsg = `Request Signature:
---[ CANONICAL STRING  ]-----------------------------
%s
---[ STRING TO SIGN ]--------------------------------
%s%s
-----------------------------------------------------`
const logSignedURLMsg = `
---[ SIGNED URL ]------------------------------------
%s`
