//go:build requirefips

package sarama

import "errors"

type GSSAPIKerberosAuth struct{}

func (b *Broker) sendAndReceiveKerberos() error {
	return errors.New("kerberos not allowed in fips mode")
}

func (b *Broker) sendAndReceiveKerberosV2(
	authSendReceiver func(authBytes []byte) (*SaslAuthenticateResponse, error),
) error {
	return errors.New("kerberos not allowed in fips mode")
}
