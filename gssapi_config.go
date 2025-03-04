package sarama

const (
	TOK_ID_KRB_AP_REQ   = 256
	GSS_API_GENERIC_TAG = 0x60
	KRB5_USER_AUTH      = 1
	KRB5_KEYTAB_AUTH    = 2
	KRB5_CCACHE_AUTH    = 3
	GSS_API_INITIAL     = 1
	GSS_API_VERIFY      = 2
	GSS_API_FINISH      = 3
)

type GSSAPIConfig struct {
	AuthType           int
	KeyTabPath         string
	CCachePath         string
	KerberosConfigPath string
	ServiceName        string
	Username           string
	Password           string
	Realm              string
	DisablePAFXFAST    bool
	BuildSpn           BuildSpnFunc
}

type BuildSpnFunc func(serviceName, host string) string
