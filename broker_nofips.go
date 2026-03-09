//go:build !requirefips

package sarama

func (b *Broker) sendAndReceiveKerberos() error {
	b.kerberosAuthenticator.Config = &b.conf.Net.SASL.GSSAPI
	if b.kerberosAuthenticator.NewKerberosClientFunc == nil {
		b.kerberosAuthenticator.NewKerberosClientFunc = NewKerberosClient
	}
	return b.kerberosAuthenticator.Authorize(b)
}

func (b *Broker) sendAndReceiveKerberosV2(
	authSendReceiver func(authBytes []byte) (*SaslAuthenticateResponse, error),
) error {
	b.kerberosAuthenticator.Config = &b.conf.Net.SASL.GSSAPI
	if b.kerberosAuthenticator.NewKerberosClientFunc == nil {
		b.kerberosAuthenticator.NewKerberosClientFunc = NewKerberosClient
	}
	return b.kerberosAuthenticator.AuthorizeV2(b, authSendReceiver)
}
