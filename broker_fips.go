//go:build requirefips

package sarama

import "errors"

type GSSAPIKerberosAuth struct{}

func (b *Broker) sendAndReceiveKerberos() error {
	return errors.New("kerberos not allowed in fips mode")
}
