//go:build !requirefips

package sarama

func (b *Broker) sendAndReceiveKerberos() error {
	b.kerberosAuthenticator.Config = &b.conf.Net.SASL.GSSAPI
	if b.kerberosAuthenticator.NewKerberosClientFunc == nil {
		b.kerberosAuthenticator.NewKerberosClientFunc = NewKerberosClient
	}
	return b.kerberosAuthenticator.Authorize(b)
}
