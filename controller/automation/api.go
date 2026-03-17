package automation

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/openziti/edge-api/rest_management_api_client"
	"github.com/openziti/edge-api/rest_util"
	"github.com/pkg/errors"
)

type Config struct {
	ApiEndpoint string
	Username    string
	Password    string `dd:"+secret"`
}

type ZitiAutomation struct {
	edge                      *rest_management_api_client.ZitiEdgeManagement
	Identities                *IdentityManager
	Services                  *ServiceManager
	Configs                   *ConfigManager
	ConfigTypes               *ConfigTypeManager
	EdgeRouterPolicies        *EdgeRouterPolicyManager
	ServiceEdgeRouterPolicies *ServiceEdgeRouterPolicyManager
	ServicePolicies           *ServicePolicyManager
}

func NewZitiAutomation(cfg *Config) (*ZitiAutomation, error) {
	caCerts, err := rest_util.GetControllerWellKnownCas(cfg.ApiEndpoint)
	if err != nil {
		return nil, err
	}
	caPool := x509.NewCertPool()
	for _, ca := range caCerts {
		caPool.AddCert(ca)
	}

	// 检查是否是IP地址连接
	isIPAddress, err := isIPAddressEndpoint(cfg.ApiEndpoint)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing API endpoint")
	}

	var edge *rest_management_api_client.ZitiEdgeManagement
	if isIPAddress {
		// 使用IP地址时，创建自定义TLS配置：验证CA但跳过主机名验证
		edge, err = newEdgeManagementClientWithIPAddress(cfg.Username, cfg.Password, cfg.ApiEndpoint, caPool)
		if err != nil {
			return nil, err
		}
	} else {
		// 使用域名时，正常验证
		edge, err = rest_util.NewEdgeManagementClientWithUpdb(cfg.Username, cfg.Password, cfg.ApiEndpoint, caPool)
		if err != nil {
			return nil, err
		}
	}
	ziti := &ZitiAutomation{edge: edge}
	ziti.Identities = NewIdentityManager(ziti)
	ziti.Services = NewServiceManager(ziti)
	ziti.Configs = NewConfigManager(ziti)
	ziti.ConfigTypes = NewConfigTypeManager(ziti)
	ziti.EdgeRouterPolicies = NewEdgeRouterPolicyManager(ziti)
	ziti.ServiceEdgeRouterPolicies = NewServiceEdgeRouterPolicyManager(ziti)
	ziti.ServicePolicies = NewServicePolicyManager(ziti)
	return ziti, nil
}

func isIPAddressEndpoint(apiEndpoint string) (bool, error) {
	u, err := url.Parse(apiEndpoint)
	if err != nil {
		return false, err
	}

	// 提取主机名（去掉端口）
	host := u.Host
	if colonIdx := strings.Index(host, ":"); colonIdx != -1 {
		host = host[:colonIdx]
	}

	// 检查是否是IP地址格式
	return net.ParseIP(host) != nil, nil
}

func newEdgeManagementClientWithIPAddress(username, password string, apiAddress string, rootCas *x509.CertPool) (*rest_management_api_client.ZitiEdgeManagement, error) {
	auth := rest_util.NewAuthenticatorUpdb(username, password)
	auth.RootCas = rootCas

	// 创建自定义TLS配置，验证CA但跳过主机名验证
	auth.TlsConfigFunc = func() (*tls.Config, error) {
		tlsConfig, err := rest_util.NewTlsConfig()
		if err != nil {
			return nil, err
		}

		// 保留原有的CA验证，但自定义验证逻辑
		tlsConfig.RootCAs = rootCas

		// 自定义验证函数：验证证书由受信任CA签发，但跳过主机名验证
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
				Roots:         rootCas,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range certs[1:] {
				opts.Intermediates.AddCert(cert)
			}

			_, err := certs[0].Verify(opts)
			return err
		}

		return tlsConfig, nil
	}

	return rest_util.NewEdgeManagementClientWithAuthenticator(auth, apiAddress)
}

func (za *ZitiAutomation) Edge() *rest_management_api_client.ZitiEdgeManagement {
	return za.edge
}

// error helper methods to simplify error handling

func (za *ZitiAutomation) IsNotFound(err error) bool {
	var automationErr *AutomationError
	if errors.As(err, &automationErr) {
		return automationErr.IsNotFound()
	}
	return false
}

func (za *ZitiAutomation) ShouldRetry(err error) bool {
	var automationErr *AutomationError
	if errors.As(err, &automationErr) {
		return automationErr.IsRetryable()
	}
	return false
}

func (za *ZitiAutomation) CleanupByTag(tag, value string) error {
	var filter string
	if value == "*" {
		// cleanup all resources with the tag (any value)
		filter = fmt.Sprintf("tags.%s != null", tag)
	} else {
		// cleanup resources with specific tag value
		filter = BuildTagFilter(tag, value)
	}

	// delete service edge router policies
	if err := za.ServiceEdgeRouterPolicies.DeleteWithFilter(filter); err != nil {
		return errors.Wrap(err, "failed to delete service edge router policies")
	}

	// delete service policies
	if err := za.ServicePolicies.DeleteWithFilter(filter); err != nil {
		return errors.Wrap(err, "failed to delete service policies")
	}

	// delete configs
	if err := za.Configs.DeleteWithFilter(filter); err != nil {
		return errors.Wrap(err, "failed to delete configs")
	}

	// delete services
	if err := za.Services.DeleteWithFilter(filter); err != nil {
		return errors.Wrap(err, "failed to delete services")
	}

	// delete edge router policies
	if err := za.EdgeRouterPolicies.DeleteWithFilter(filter); err != nil {
		return errors.Wrap(err, "failed to delete edge router policies")
	}

	// find and delete identities
	if err := za.Identities.DeleteWithFilter(filter); err != nil {
		return errors.Wrap(err, "failed to delete identities")
	}

	return nil
}

const (
	// DefaultRequestTimeout is the default timeout for API requests
	DefaultRequestTimeout = 30 * time.Second

	// DefaultOperationTimeout is the default timeout for CRUD operations
	DefaultOperationTimeout = 30 * time.Second
)
