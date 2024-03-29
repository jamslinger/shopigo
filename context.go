package shopigo

import "github.com/gin-gonic/gin"

type authMetadata struct {
	shop        string
	redirectURI string
}

func setShop(c *gin.Context, shop string) {
	if _, ok := c.Get(metadataKey); !ok {
		c.Set(metadataKey, authMetadata{})
	}
	d := mustGetMetaData(c)
	d.shop = shop
	c.Set(metadataKey, d)
}

func setRedirectURI(c *gin.Context, redirectURI string) {
	if _, ok := c.Get(metadataKey); !ok {
		c.Set(metadataKey, authMetadata{})
	}
	d := mustGetMetaData(c)
	d.redirectURI = redirectURI
	c.Set(metadataKey, d)
}

func mustGetMetaData(c *gin.Context) authMetadata {
	d, ok := c.MustGet(metadataKey).(authMetadata)
	if !ok {
		panic("gin context must contain authMetadata")
	}
	return d
}

func getMetaData(c *gin.Context) (md authMetadata) {
	d, ok := c.Get(metadataKey)
	if !ok {
		return
	}
	return d.(authMetadata)
}

func mustGetShop(c *gin.Context) string {
	return mustGetMetaData(c).shop
}

func getShop(c *gin.Context) string {
	return getMetaData(c).shop
}

func mustGetRedirectURI(c *gin.Context) string {
	return mustGetMetaData(c).redirectURI
}
