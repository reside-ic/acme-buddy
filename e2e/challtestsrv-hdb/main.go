// This is a mock version of the ICT HDB API, using challtestsrv to serve the
// DNS TXT records. It does not perform any authentication checks. It also does
// not setup an indirection with a CNAME the way that HDB does.

package main

import (
	"errors"
	"log"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/letsencrypt/challtestsrv"
)

type request struct {
	Token string `json:"token"`
}

func main() {
	challSrv, err := challtestsrv.New(challtestsrv.Config{DNSOneAddrs: []string{":8053"}})
	if err != nil {
		log.Fatalf("cannot start challtestsrv: %v", err)
	}
	go challSrv.Run()

	router := gin.Default()
	router.Match([]string{"PUT", "DELETE"}, "/:fqdn/auth_token", func(c *gin.Context) {
		fqdn := c.Param("fqdn")
		r := request{}
		if c.BindJSON(&r) != nil {
			return
		}

		// For some reason HDB expects the string to be quoted (in addition to the
		// normal JSON quoting).
		token, err := strconv.Unquote(r.Token)
		if err != nil {
			c.AbortWithError(400, err)
			return
		}

		// HDB refuses the trailing dot usually found on FQDN. challtestsrv expects
		// it though, so we make sure to add it.
		if strings.HasSuffix(fqdn, ".") {
			c.AbortWithError(400, errors.New("invalid fqdn"))
			return
		}
		fqdn = fqdn + "."

		if c.Request.Method == "PUT" {
			challSrv.AddDNSOneChallenge(fqdn, token)
		} else {
			// challtestsrv doesn't have a method to remove just a specific TXT
			// entry. Instead it removes all entries. That is fine as long as we
			// don't run tests in parallel.
			challSrv.DeleteDNSOneChallenge(fqdn)
		}
	})
	router.Run()
}
