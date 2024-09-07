package shopigo

import (
	"github.com/stretchr/testify/assert"
	"net/url"
	"testing"
)

func TestValidateHMAC(t *testing.T) {
	u, err := url.Parse("https://example.com?timestamp=1337178173&code=0907a61c0c8d55e99db179b68161bc00&hmac=700e2dadb827fcc8609e9d5ce208b2e9cdaab9df07390d2cbca10d7c328fc4bf&state=0.6784241404160823&shop={shop}.myshopify.com")
	assert.NoError(t, err)

	h, rest := parseHMAC(u.Query())
	assert.Equal(t, h, "700e2dadb827fcc8609e9d5ce208b2e9cdaab9df07390d2cbca10d7c328fc4bf")
	assert.Equal(t, rest, "code=0907a61c0c8d55e99db179b68161bc00&shop={shop}.myshopify.com&state=0.6784241404160823&timestamp=1337178173")
}
