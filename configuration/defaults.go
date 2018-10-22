package configuration

const (
	defaultHeaderMaxLength = 5000 // bytes

	// Auth-related defaults

	// RSAPrivateKey for signing JWT Tokens for service accounts
	// ssh-keygen -f auth_rsa
	DefaultServiceAccountPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAnwrjH5iTSErw9xUptp6QSFoUfpHUXZ+PaslYSUrpLjw1q27O
DSFwmhV4+dAaTMO5chFv/kM36H3ZOyA146nwxBobS723okFaIkshRrf6qgtD6coT
HlVUSBTAcwKEjNn4C9jtEpyOl+eSgxhMzRH3bwTIFlLlVMiZf7XVE7P3yuOCpqkk
2rdYVSpQWQWKU+ZRywJkYcLwjEYjc70AoNpjO5QnY+Exx98E30iEdPHZpsfNhsjh
9Z7IX5TrMYgz7zBTw8+niO/uq3RBaHyIhDbvenbR9Q59d88lbnEeHKgSMe2RQpFR
3rxFRkc/64Rn/bMuL/ptNowPqh1P+9GjYzWmPwIDAQABAoIBAQCBCl5ZpnvprhRx
BVTA/Upnyd7TCxNZmzrME+10Gjmz79pD7DV25ejsu/taBYUxP6TZbliF3pggJOv6
UxomTB4znlMDUz0JgyjUpkyril7xVQ6XRAPbGrS1f1Def+54MepWAn3oGeqASb3Q
bAj0Yl12UFTf+AZmkhQpUKk/wUeN718EIY4GRHHQ6ykMSqCKvdnVbMyb9sIzbSTl
v+l1nQFnB/neyJq6P0Q7cxlhVj03IhYj/AxveNlKqZd2Ih3m/CJo0Abtwhx+qHZp
cCBrYj7VelEaGARTmfoIVoGxFGKZNCcNzn7R2ic7safxXqeEnxugsAYX/UmMoq1b
vMYLcaLRAoGBAMqMbbgejbD8Cy6wa5yg7XquqOP5gPdIYYS88TkQTp+razDqKPIU
hPKetnTDJ7PZleOLE6eJ+dQJ8gl6D/dtOsl4lVRy/BU74dk0fYMiEfiJMYEYuAU0
MCramo3HAeySTP8pxSLFYqJVhcTpL9+NQgbpJBUlx5bLDlJPl7auY077AoGBAMkD
UpJRIv/0gYSz5btVheEyDzcqzOMZUVsngabH7aoQ49VjKrfLzJ9WznzJS5gZF58P
vB7RLuIA8m8Y4FUwxOr4w9WOevzlFh0gyzgNY4gCwrzEryOZqYYqCN+8QLWfq/hL
+gYFYpEW5pJ/lAy2i8kPanC3DyoqiZCsUmlg6JKNAoGBAIdCkf6zgKGhHwKV07cs
DIqx2p0rQEFid6UB3ADkb+zWt2VZ6fAHXeT7shJ1RK0o75ydgomObWR5I8XKWqE7
s1dZjDdx9f9kFuVK1Upd1SxoycNRM4peGJB1nWJydEl8RajcRwZ6U+zeOc+OfWbH
WUFuLadlrEx5212CQ2k+OZlDAoGAdsH2w6kZ83xCFOOv41ioqx5HLQGlYLpxfVg+
2gkeWa523HglIcdPEghYIBNRDQAuG3RRYSeW+kEy+f4Jc2tHu8bS9FWkRcsWoIji
ZzBJ0G5JHPtaub6sEC6/ZWe0F1nJYP2KLop57FxKRt0G2+fxeA0ahpMwa2oMMiQM
4GM3pHUCgYEAj2ZjjsF2MXYA6kuPUG1vyY9pvj1n4fyEEoV/zxY1k56UKboVOtYr
BA/cKaLPqUF+08Tz/9MPBw51UH4GYfppA/x0ktc8998984FeIpfIFX6I2U9yUnoQ
OCCAgsB8g8yTB4qntAYyfofEoDiseKrngQT5DSdxd51A/jw7B8WyBK8=
-----END RSA PRIVATE KEY-----`

	defaultServiceAccountPrivateKeyID = "9MLnViaRkhVj1GT9kpWUkwHIwUD-wZfUxR-3CpkE-Xs"

	DefaultUserAccountPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA40yB6SNoU4SpWxTfG5ilu+BlLYikRyyEcJIGg//w/GyqtjvT
/CVo92DRTh/DlrgwjSitmZrhauBnrCOoUBMin0/TXeSo3w2M5tEiiIFPbTDRf2jM
fbSGEOke9O0USCCR+bM2TncrgZR74qlSwq38VCND4zHc89rAzqJ2LVM2aXkuBbO7
TcgLNyooBrpOK9khVHAD64cyODAdJY4esUjcLdlcB7TMDGOgxGGn2RARU7+TUf32
gZZbTMikbuPM5gXuzGlo/22ECbQSKuZpbGwgPIAZ5NN9QA4D1NRz9+KDoiXZ6deZ
TTVCrZykJJ6RyLNfRh+XS+6G5nvcqAmfBpyOWwIDAQABAoIBAE5pBie23zZwfTu+
Z3jNn96/+idLC+DBqq5qsXS3xhpOIlXbLbW98gfkjk+1BXPo9la7wadLlpeX8iuf
4WA+OaNblj69ssO/mOvHGXKdqRixzpN1Q5XZwKX0xYkYf/ahxbmt6P4IfimlX1dB
shsWigU8ZR7rBJ3ayMh/ouTf39ViIbXsHYpEubmACcLaOlXbEuZNr7ofkFQKl/mh
XLWUeOoM97xY6Agw/gv60GIcxIC5OAg7iNqS+XNzhba7f2nf2YqodbN9H1BmEJsf
RRaTTWlZAiQXC8lpZOKwP7DiMLOT78lfmlYtquEBhwRbXazfzsdf67Mr4Kdl2Cej
Jy0EGwECgYEA/DZWB0Lb0tPdT1FmORNrBfGg3PjhX9FOilhbtUgX3nNKp8Zsi3yO
yN6hf0/98qIGlmAQi5C92cXpdhqTiVAGktWD+q0a1W99udIjinS1tFrKgNtOyBWN
uwDBZyhw8RrwpQinMe7B966SVDaphvvOWlB1TadMDh5kReJCYpvRCrMCgYEA5rZj
djCU2UqMw6jIP07nCFjWgxPPjg7jP8aRo07oW2mv1sEA0doCyoZaMrdNeGd3fB0B
sm+IvlQtWD7r0tWZI1GkYpdRkDFurdkIzVPV5pMwH4ByOq/Jf5ZqtjIpoMaRBirA
whJyjmiGU3yDyPDLtEFpNgqM3mIyxS6M6UGKYbkCgYEAg6w+d6YBK+1uQiXGD5BC
tKS0jgjlaOfWcEW3A0qzI3Dfjf3610vdI6OPfu8dLppGhCV9HdAgPdykiQNQ+UQt
WmVcdPgA5WNCqUu7QGK0Joer52AXnkAacYHwdtHXPRkKf66n01rKK2wZexvan91A
m0gcJcFs5IYbZZy9ecvNdB8CgYEAo4JZ5Vay93j1YGnLWcrixDCp/wXYUJbOidGC
QBpZZQf3Hh11JkT7O2uSm2T727yAmw63uC2B3VotNOCLI8ZMHRLsjQ8vOCFAjqdF
rLeg3iQss/bFfkA9b1Y8VNoiVJbGC3fbWu/WDoWXxa12fL/jruG43hsGEUnJL6Q5
K8tOdskCgYABpoHFRxsvJ5Sp9CUS3BBTicVSkpAjoX2O3+cS9XL8IsIqZEMW7VKb
16/H2BRvI0uUq12t+UCc0P0SyrWRGxwGR5zSYHVDOot5EDHqE8aYSbX4jiXtAAiu
qCn3Rug8QWyBjjxnU3CxPRiLSmEllQAAVlzfRWn6kL4RKSyruUhZaA==
-----END RSA PRIVATE KEY-----`

	defaultUserAccountPrivateKeyID = "aUGv8mQA85jg4V1DU8Uk1W0uKsxn187KQONAGl6AMtc"

	devModePublicKey = `-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvQ8p+HsTMrgcsuIMoOR1
LXRhynL9YAU0qoDON6PLKCpdBv0Xy/jnsPjo5DrtUOijuJcID8CR7E0hYpY9MgK5
H5pDFwC4lbUVENquHEVS/E0pQSKCIzSmORcIhjYW2+wKfDOVjeudZwdFBIxJ6KpI
ty/aF78hlUJZuvghFVqoHQYTq/DZOmKjS+PAVLw8FKE3wa/3WU0EkpP+iovRMCkl
lzxqrcLPIvx+T2gkwe0bn0kTvdMOhTLTN2tuvKrFpVUxVi8RM/V8PtgdKroxnES7
SyUqK8rLO830jKJzAYrByQL+sdGuSqInIY/geahQHEGTwMI0CLj6zfhpjSgCflst
vwIDAQAB
-----END RSA PUBLIC KEY-----`

	devModePublicKeyID = "bNq-BCOR3ev-E6buGSaPrU-0SXX8whhDlmZ6geenkTE"

	defaultDBPassword = "mysecretpassword"

	defaultGitHubClientSecret = "48d1498c849616dfecf83cf74f22dfb361ee2511"

	defaultLogLevel = "info"

	// OAuth Provider defaults

	defaultOAuthClientID = "fabric8-online-platform"
	defaultOAuthSecret   = "7a3d5a00-7f80-40cf-8781-b5b6f2dfd1bd"

	defaultPublicOAuthClientID  = "740650a2-9c44-4db5-b067-a3d1b2cd2d01"
	defaultKeycloakDomainPrefix = "sso"
	defaultKeycloakRealm        = "fabric8"
	defaultWITDomainPrefix      = "api"

	// Keycloak vars to be used in dev mode. Can be overridden by setting up keycloak.url & keycloak.realm
	devModeKeycloakURL   = "https://sso.prod-preview.openshift.io"
	devModeKeycloakRealm = "fabric8-test"
	devModeWITURL        = "http://localhost:8080"

	// DefaultValidRedirectURLs is a regex to be used to whitelist redirect URL for auth
	// If the AUTH_REDIRECT_VALID env var is not set then in Dev Mode all redirects allowed - *
	// In prod mode the following regex will be used by default:
	DefaultValidRedirectURLs = "^(https|http)://(([^/?#]+[.])?(?i:openshift[.]io)|localhost|(?i:rhche-dfestal-preview-che[.]devtools-dev[.]ext[.]devshift[.]net))((/|:).*)?$" //"^(https|http)://(([^/?#]+[.])?(?i:openshift[.]io)|localhost)((/|:).*)?$" // *.openshift.io/* and localhost
	devModeValidRedirectURLs = ".*"

	serviceAccountConfigFileName    = "service-account-secrets.conf"
	defaultServiceAccountConfigPath = "/etc/fabric8/" + serviceAccountConfigFileName

	prodEnvironment        = "production"
	prodPreviewEnvironment = "prod-preview"
)
