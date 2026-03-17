package env_v0_4

import (
	"crypto/x509"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/openziti/edge-api/rest_util"
	"github.com/openziti/zrok/v2/build"
	"github.com/openziti/zrok/v2/environment/env_core"
	"github.com/openziti/zrok/v2/rest_client_zrok"
	metadata2 "github.com/openziti/zrok/v2/rest_client_zrok/metadata"
	"github.com/pkg/errors"
)

func (r *Root) Metadata() *env_core.Metadata {
	return r.meta
}

func (r *Root) HasConfig() (bool, error) {
	return r.cfg != nil, nil
}

func (r *Root) Config() *env_core.Config {
	return r.cfg
}

func (r *Root) SetConfig(cfg *env_core.Config) error {
	if err := assertMetadata(); err != nil {
		return err
	}
	if err := saveConfig(cfg); err != nil {
		return err
	}
	r.cfg = cfg
	return nil
}

func (r *Root) Client() (*rest_client_zrok.Zrok, error) {
	apiEndpoint, _ := r.ApiEndpoint()
	apiUrl, err := url.Parse(apiEndpoint)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing api endpoint '%v'", r)
	}

	// 检测是否是IP地址
	isIPAddress := isIPAddressEndpoint(apiEndpoint)

	transport := httptransport.New(apiUrl.Host, "/api/v2", []string{apiUrl.Scheme})
	transport.Producers["application/zrok.v1+json"] = runtime.JSONProducer()
	transport.Consumers["application/zrok.v1+json"] = runtime.JSONConsumer()

	// 如果是IP地址，配置自定义TLS验证
	if isIPAddress && apiUrl.Scheme == "https" {
		// 获取服务器的CA证书（使用InsecureSkipVerify）
		caCerts, err := rest_util.GetControllerWellKnownCas(apiEndpoint)
		if err != nil {
			return nil, errors.Wrapf(err, "error getting CA certs for api endpoint '%v': %v", apiEndpoint, err)
		}
		caPool := x509.NewCertPool()
		for _, ca := range caCerts {
			caPool.AddCert(ca)
		}

		// 创建自定义TLS配置
		tlsConfig, err := rest_util.NewTlsConfig()
		if err != nil {
			return nil, errors.Wrap(err, "error creating TLS config")
		}
		tlsConfig.RootCAs = caPool
		tlsConfig.InsecureSkipVerify = true // 先跳过默认验证
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			certs := make([]*x509.Certificate, len(rawCerts))
			for i, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return err
				}
				certs[i] = cert
			}

			// 验证证书链
			opts := x509.VerifyOptions{
				Roots:         caPool,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range certs[1:] {
				opts.Intermediates.AddCert(cert)
			}

			_, err := certs[0].Verify(opts)
			return err
		}

		// 创建自定义HTTP客户端
		httpClient, err := rest_util.NewHttpClientWithTlsConfig(tlsConfig)
		if err != nil {
			return nil, errors.Wrap(err, "error creating HTTP client with custom TLS config")
		}
		transport = httptransport.NewWithClient(apiUrl.Host, "/api/v2", []string{apiUrl.Scheme}, httpClient)
	}

	zrok := rest_client_zrok.New(transport, strfmt.Default)
	_, err = zrok.Metadata.ClientVersionCheck(&metadata2.ClientVersionCheckParams{
		Body: metadata2.ClientVersionCheckBody{
			ClientVersion: build.String(),
		},
	})
	if err != nil {
		return nil, errors.Wrapf(err, "client version error accessing api endpoint '%v': %v", apiEndpoint, err)
	}
	return zrok, nil
}

func isIPAddressEndpoint(apiEndpoint string) bool {
	u, err := url.Parse(apiEndpoint)
	if err != nil {
		return false
	}

	// 提取主机名（去掉端口）
	host := u.Host
	if colonIdx := strings.Index(host, ":"); colonIdx != -1 {
		host = host[:colonIdx]
	}

	// 检查是否是IP地址格式
	return net.ParseIP(host) != nil
}

func (r *Root) ApiEndpoint() (string, string) {
	apiEndpoint := "https://api-v2.zrok.io"
	from := "binary"

	if r.Config() != nil && r.Config().ApiEndpoint != "" {
		apiEndpoint = r.Config().ApiEndpoint
		from = "config"
	}

	env := os.Getenv("ZROK2_API_ENDPOINT")
	if env != "" {
		apiEndpoint = env
		from = "ZROK2_API_ENDPOINT"
	}

	if r.IsEnabled() {
		apiEndpoint = r.Environment().ApiEndpoint
		from = "env"
	}

	return apiEndpoint, from
}

func (r *Root) DefaultNamespace() (string, string) {
	defaultNamespace := "public"
	from := "binary"

	if r.Config() != nil && r.Config().DefaultNamespace != "" {
		defaultNamespace = r.Config().DefaultNamespace
		from = "config"
	}

	env := os.Getenv("ZROK2_DEFAULT_NAMESPACE")
	if env != "" {
		defaultNamespace = env
		from = "ZROK2_DEFAULT_NAMESPACE"
	}

	return defaultNamespace, from
}

func (r *Root) Headless() (bool, string) {
	headless := false
	from := "binary"

	if r.Config() != nil {
		headless = r.Config().Headless
		from = "config"
	}

	env := os.Getenv("ZROK2_HEADLESS")
	if env != "" {
		if v, err := strconv.ParseBool(env); err == nil {
			headless = v
			from = "ZROK2_HEADLESS"
		}
	}

	return headless, from
}

func (r *Root) SuperNetwork() (bool, string) {
	superNetwork := false
	from := "binary"

	if r.Config() != nil {
		superNetwork = r.Config().SuperNetwork
		from = "config"
	}

	env := os.Getenv("ZROK2_SUPER_NETWORK")
	if env != "" {
		if v, err := strconv.ParseBool(env); err == nil {
			superNetwork = v
			from = "ZROK2_SUPER_NETWORK"
		}
	}

	return superNetwork, from
}

func (r *Root) Environment() *env_core.Environment {
	return r.env
}

func (r *Root) SetEnvironment(env *env_core.Environment) error {
	if err := assertMetadata(); err != nil {
		return err
	}
	if err := saveEnvironment(env); err != nil {
		return err
	}
	r.env = env
	return nil
}

func (r *Root) DeleteEnvironment() error {
	ef, err := environmentFile()
	if err != nil {
		return errors.Wrap(err, "error getting environment file")
	}
	if err := os.Remove(ef); err != nil {
		return errors.Wrap(err, "error removing environment file")
	}
	r.env = nil
	return nil
}

func (r *Root) IsEnabled() bool {
	return r.env != nil
}

func (r *Root) PublicIdentityName() string {
	return "public"
}

func (r *Root) EnvironmentIdentityName() string {
	return "environment"
}

func (r *Root) ZitiIdentityNamed(name string) (string, error) {
	return identityFile(name)
}

func (r *Root) SaveZitiIdentityNamed(name, data string) error {
	if err := assertMetadata(); err != nil {
		return err
	}
	zif, err := r.ZitiIdentityNamed(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(zif), os.FileMode(0700)); err != nil {
		return errors.Wrapf(err, "error creating environment path '%v'", filepath.Dir(zif))
	}
	if err := os.WriteFile(zif, []byte(data), os.FileMode(0600)); err != nil {
		return errors.Wrapf(err, "error writing ziti identity file '%v'", zif)
	}
	return nil
}

func (r *Root) DeleteZitiIdentityNamed(name string) error {
	zif, err := r.ZitiIdentityNamed(name)
	if err != nil {
		return errors.Wrapf(err, "error getting ziti identity file path for '%v'", name)
	}
	if err := os.Remove(zif); err != nil {
		return errors.Wrapf(err, "error removing ziti identity file '%v'", zif)
	}
	return nil
}

func (r *Root) AgentSocket() (string, error) {
	return agentSocket()
}

func (r *Root) AgentRegistry() (string, error) {
	return agentRegistry()
}

func (r *Root) AgentEnrollment() (string, error) {
	return agentEnrollment()
}

func (r *Root) Obliterate() error {
	zrd, err := rootDir()
	if err != nil {
		return err
	}
	if err := os.RemoveAll(zrd); err != nil {
		return err
	}
	return nil
}
