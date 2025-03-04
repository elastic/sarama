//go:build !requirefips

package sarama

import (
	"errors"
	"testing"

	"github.com/jcmturner/gokrb5/v8/krberror"
	"github.com/rcrowley/go-metrics"
)

func TestGSSAPIKerberosAuth_Authorize(t *testing.T) {
	testTable := []struct {
		name               string
		error              error
		mockKerberosClient bool
		errorStage         string
		badResponse        bool
		badKeyChecksum     bool
	}{
		{
			name:               "Kerberos authentication success",
			error:              nil,
			mockKerberosClient: true,
		},
		{
			name: "Kerberos login fails",
			error: krberror.NewErrorf(krberror.KDCError, "KDC_Error: AS Exchange Error: "+
				"kerberos error response from KDC: KRB Error: (24) KDC_ERR_PREAUTH_FAILED Pre-authenti"+
				"cation information was invalid - PREAUTH_FAILED"),
			mockKerberosClient: true,
			errorStage:         "login",
		},
		{
			name: "Kerberos service ticket fails",
			error: krberror.NewErrorf(krberror.KDCError, "KDC_Error: AS Exchange Error: "+
				"kerberos error response from KDC: KRB Error: (24) KDC_ERR_PREAUTH_FAILED Pre-authenti"+
				"cation information was invalid - PREAUTH_FAILED"),
			mockKerberosClient: true,
			errorStage:         "service_ticket",
		},
		{
			name:  "Kerberos client creation fails",
			error: errors.New("configuration file could not be opened: krb5.conf open krb5.conf: no such file or directory"),
		},
		{
			name:               "Bad server response, unmarshall key error",
			error:              errors.New("bytes shorter than header length"),
			badResponse:        true,
			mockKerberosClient: true,
		},
		{
			name:               "Bad token checksum",
			error:              errors.New("checksum mismatch. Computed: 39feb88ac2459f2b77738493, Contained in token: ffffffffffffffff00000000"),
			badResponse:        false,
			badKeyChecksum:     true,
			mockKerberosClient: true,
		},
	}
	for i, test := range testTable {
		test := test
		t.Run(test.name, func(t *testing.T) {
			mockBroker := NewMockBroker(t, 0)
			// broker executes SASL requests against mockBroker

			mockBroker.SetGSSAPIHandler(func(bytes []byte) []byte {
				return nil
			})
			broker := NewBroker(mockBroker.Addr())
			broker.requestRate = metrics.NilMeter{}
			broker.outgoingByteRate = metrics.NilMeter{}
			broker.incomingByteRate = metrics.NilMeter{}
			broker.requestSize = metrics.NilHistogram{}
			broker.responseSize = metrics.NilHistogram{}
			broker.responseRate = metrics.NilMeter{}
			broker.requestLatency = metrics.NilHistogram{}
			broker.requestsInFlight = metrics.NilCounter{}

			conf := NewTestConfig()
			conf.Net.SASL.Mechanism = SASLTypeGSSAPI
			conf.Net.SASL.Enable = true
			conf.Net.SASL.GSSAPI.ServiceName = "kafka"
			conf.Net.SASL.GSSAPI.KerberosConfigPath = "krb5.conf"
			conf.Net.SASL.GSSAPI.Realm = "EXAMPLE.COM"
			conf.Net.SASL.GSSAPI.Username = "kafka"
			conf.Net.SASL.GSSAPI.Password = "kafka"
			conf.Net.SASL.GSSAPI.KeyTabPath = "kafka.keytab"
			conf.Net.SASL.GSSAPI.AuthType = KRB5_USER_AUTH
			conf.Version = V1_0_0_0

			gssapiHandler := KafkaGSSAPIHandler{
				client:         &MockKerberosClient{},
				badResponse:    test.badResponse,
				badKeyChecksum: test.badKeyChecksum,
			}
			mockBroker.SetGSSAPIHandler(gssapiHandler.MockKafkaGSSAPI)
			if test.mockKerberosClient {
				broker.kerberosAuthenticator.NewKerberosClientFunc = func(config *GSSAPIConfig) (KerberosClient, error) {
					return &MockKerberosClient{
						mockError:  test.error,
						errorStage: test.errorStage,
					}, nil
				}
			} else {
				broker.kerberosAuthenticator.NewKerberosClientFunc = nil
			}

			err := broker.Open(conf)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = broker.Close() })

			_, err = broker.Connected()

			if err != nil && test.error != nil {
				if test.error.Error() != err.Error() {
					t.Errorf("[%d] Expected error:%s, got:%s.", i, test.error, err)
				}
			} else if (err == nil && test.error != nil) || (err != nil && test.error == nil) {
				t.Errorf("[%d] Expected error:%s, got:%s.", i, test.error, err)
			}

			mockBroker.Close()
		})
	}
}
