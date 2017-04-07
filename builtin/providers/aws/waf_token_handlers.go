package aws

import (
	"github.com/aws/aws-sdk-go/service/waf"
)

type WAFToken struct {
	Connection *waf.WAF
	Region     string
}

func (t *WAFToken) Acquire() (*string, error) {
	awsMutexKV.Lock(t.Region)

	out, err := t.Connection.GetChangeToken(&waf.GetChangeTokenInput{})
	if err != nil {
		t.Release()
		return nil, err
	}

	return out.ChangeToken, nil
}

func (t *WAFToken) Release() {
	awsMutexKV.Unlock(t.Region)
}

func newWAFToken(conn *waf.WAF, region string) *WAFToken {
	return &WAFToken{Connection: conn, Region: region}
}
