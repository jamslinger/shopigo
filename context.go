package shopigo

import "github.com/gin-gonic/gin"

type authMetadata struct {
	shop        string
	host        string
	redirectUri string
}

func setShop(c *gin.Context, shop string) {
	if _, ok := c.Get(metadataKey); !ok {
		c.Set(metadataKey, authMetadata{})
	}
	d := mustGetMetaData(c)
	d.shop = shop
	c.Set(metadataKey, d)
}

func setRedirectUri(c *gin.Context, redirectUri string) {
	if _, ok := c.Get(metadataKey); !ok {
		c.Set(metadataKey, authMetadata{})
	}
	d := mustGetMetaData(c)
	d.redirectUri = redirectUri
	c.Set(metadataKey, d)
}

func mustGetMetaData(c *gin.Context) authMetadata {
	d, ok := c.MustGet(metadataKey).(authMetadata)
	if !ok {
		panic("gin context must contain authMetadata")
	}
	return d
}

func mustGetShop(c *gin.Context) string {
	return mustGetMetaData(c).shop
}

func mustGetRedirectUri(c *gin.Context) string {
	return mustGetMetaData(c).redirectUri
}
