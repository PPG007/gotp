package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"hash"
	"math"
	"net/url"
	"time"
)

type Algorithm string

const (
	ALGORITHM_SHA1   Algorithm = "sha1"
	ALGORITHM_SHA256 Algorithm = "sha256"
	ALGORITHM_SHA512 Algorithm = "sha512"

	DEFAULT_DIGITS    int64 = 6
	DEFAULT_PREIOD    int64 = 30
	DEFAULT_COUNTER   int64 = 0
	DEFAULT_LABEL           = "user"
	DEFAULT_ALGORITHM       = ALGORITHM_SHA1
)

type OTPCreator interface {
	SignPassword() string
	SignURL() string
}

type common struct {
	secret    []byte
	algorithm Algorithm
	digits    int64
	period    int64
	counter   int64
	issuer    string
	label     string
}

func (c *common) init() {
	c.algorithm = DEFAULT_ALGORITHM
	c.period = DEFAULT_PREIOD
	c.digits = DEFAULT_DIGITS
	c.counter = DEFAULT_COUNTER
	c.label = DEFAULT_LABEL
}

type option = func(common *common)

func WithSecret(secret []byte) option {
	return func(common *common) {
		common.secret = secret
	}
}

func WithAlgorithm(algorithm Algorithm) option {
	return func(common *common) {
		common.algorithm = algorithm
	}
}

func WithDigits(digits int64) option {
	return func(common *common) {
		common.digits = digits
	}
}

func WithPeriod(period int64) option {
	return func(common *common) {
		common.period = period
	}
}

func WithCounter(counter int64) option {
	return func(common *common) {
		common.counter = counter
	}
}

func WithLabel(label string) option {
	return func(common *common) {
		common.label = label
	}
}

func WithIssuer(issuer string) option {
	return func(common *common) {
		common.issuer = issuer
	}
}

type totp struct {
	*common
}

func NewTOTP(options ...option) OTPCreator {
	c := &common{}
	c.init()
	for _, opt := range options {
		opt(c)
	}
	return &totp{c}
}

func (t *totp) SignURL() string {
	return signURL(
		t.secret,
		false,
		t.issuer,
		t.label,
		t.algorithm,
		t.digits,
		0,
		t.period,
	)
}

func (t *totp) SignPassword() string {
	return generateOTP(t.secret, t.algorithm, time.Now().Unix()/t.period, t.digits)
}

type hotp struct {
	*common
}

func NewHOTP(options ...option) OTPCreator {
	c := &common{}
	c.init()
	for _, opt := range options {
		opt(c)
	}
	return &hotp{c}
}

func (h *hotp) SignURL() string {
	return signURL(
		h.secret,
		true,
		h.issuer,
		h.label,
		h.algorithm,
		h.digits,
		h.counter,
		0,
	)
}

func (h *hotp) SignPassword() string {
	return generateOTP(h.secret, h.algorithm, h.counter, h.digits)
}

func I2b(integer int64) []byte {
	byteArr := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		byteArr[i] = byte(integer & 0xff)
		integer = integer >> 8
	}
	return byteArr
}

func generateOTP(secret []byte, algorithm Algorithm, counter, digits int64) string {
	hashFn := hmac.New(getHashFn(algorithm), secret)
	hashFn.Write(I2b(counter))
	result := hashFn.Sum(nil)
	offset := int(result[len(result)-1] & 0xf)
	code := ((int(result[offset]) & 0x7f) << 24) |
		((int(result[offset+1]) & 0xff) << 16) |
		((int(result[offset+2]) & 0xff) << 8) |
		(int(result[offset+3]) & 0xff)
	code = code % int(math.Pow10(int(digits)))
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", digits), code)
}

func getHashFn(algorithm Algorithm) func() hash.Hash {
	switch algorithm {
	case ALGORITHM_SHA256:
		return sha256.New
	case ALGORITHM_SHA512:
		return sha512.New
	default:
		return sha1.New
	}
}

func signURL(secret []byte, isHOTP bool, issuer, label string, algorithm Algorithm, digits, counter, period int64) string {
	query := url.Values{}
	query.Set("secret", base32.StdEncoding.EncodeToString(secret))
	query.Set("algorithm", string(algorithm))
	query.Set("digits", fmt.Sprintf("%d", digits))
	if issuer != "" {
		query.Set("issuer", issuer)
	}
	host := "totp"
	if isHOTP {
		host = "hotp"
		query.Set("counter", fmt.Sprintf("%d", counter))
	} else {
		query.Set("period", fmt.Sprintf("%d", period))
	}
	u := url.URL{
		Host:     host,
		Scheme:   "otpauth",
		RawQuery: query.Encode(),
		Path:     url.PathEscape(label),
	}
	return u.String()
}
