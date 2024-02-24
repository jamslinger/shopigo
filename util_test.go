package shopigo

import (
	"encoding/base64"
	"github.com/stretchr/testify/suite"
	"testing"
)

type UtilTestSuite struct {
	suite.Suite
}

func TestUtilTestSuite(t *testing.T) {
	suite.Run(t, new(UtilTestSuite))
}

var testConfig = &AppConfig{Credentials: &Credentials{
	ClientID:     "id",
	ClientSecret: "secret",
}}

func (s *UtilTestSuite) TestSanitizeShop() {
	for _, exp := range []string{
		"test.myshopify.com",
		"test.shopify.com",
		"test.myshopify.io",
		"test.myshopify.com/",
		"test.myshopify.com////",
		"test_123-xyz.myshopify.com",
	} {
		a, err := NewApp(testConfig)
		s.NoError(err)
		shop, err := a.sanitizeShop(exp)
		s.NoError(err)
		s.Equal(exp, shop)
	}
}

func (s *UtilTestSuite) TestSanitizeShopWithCustomDomains() {
	for _, exp := range []string{
		"test.example.com",
		"test.another-example.com",
	} {
		a, err := NewApp(testConfig, WithCustomShopDomains("example.com", "another-example.com"))
		s.NoError(err)
		shop, err := a.sanitizeShop(exp)
		s.NoError(err)
		s.Equal(exp, shop)
	}
}

func (s *UtilTestSuite) TestFailSanitizeShop() {
	for _, exp := range []string{
		"",
		"_.myshopify.com",
		"sub.test.myshopify.com",
		" test.myshopify.com",
		"sub.test.myshopify.com ",
		"test.unknown.io",
	} {
		a, err := NewApp(testConfig)
		s.NoError(err)
		_, err = a.sanitizeShop(exp)
		s.Error(err)
	}
}

func (s *UtilTestSuite) TestSanitizeHost() {
	for _, exp := range []string{
		"test.myshopify.com/test/another",
	} {
		a, err := NewApp(testConfig)
		s.NoError(err)
		shop, err := a.sanitizeHost(base64.RawURLEncoding.EncodeToString([]byte(exp)))
		s.NoError(err)
		s.Equal(exp, shop)
	}
}

func (s *UtilTestSuite) TestFailSanitizeHost() {
	for _, exp := range []string{
		base64.URLEncoding.EncodeToString([]byte("sub.test.myshopify.com/test/another")),
	} {
		a, err := NewApp(testConfig)
		s.NoError(err)
		_, err = a.sanitizeHost(exp)
		s.Error(err)
	}
}
