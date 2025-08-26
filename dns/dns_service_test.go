package dns

import (
	"crypto/tls"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

// 测试服务器名称解析功能
func TestGetServerName(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		// 域名测试
		{"dns.example.com:853", "dns.example.com"},
		{"dns.example.com", "dns.example.com"},
		{"cloudflare-dns.com:853", "cloudflare-dns.com"},

		// IPv4测试
		{"8.8.8.8:853", ""},
		{"1.1.1.1", ""},
		{"192.168.1.1:53", ""},

		// IPv6测试
		{"[2001:4860:4860::8888]:853", ""},
		{"2001:4860:4860::8844", ""},
		{"[fe80::1%eth0]:853", ""},
	}

	for _, tc := range testCases {
		result := getServerName(tc.input)
		if result != tc.expected {
			t.Errorf("getServerName(%q) 期望 %q，实际得到 %q", tc.input, tc.expected, result)
		}
	}
}

// 测试IDN转换功能
func TestIDNConversion(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"例子.中国", "xn--fsqu00a.xn--fiqs8s"},
		{"日本語.例", "xn--wgv71a119e.xn--fsq"},
		{"Müller.example", "xn--mller-kva.example"}, // 包含德语变音符号
	}

	for _, tc := range testCases {
		result, err := idna.ToASCII(tc.input)
		if err != nil {
			t.Errorf("IDN转换失败 %q: %v", tc.input, err)
			continue
		}
		if !strings.EqualFold(result, tc.expected) {
			t.Errorf("IDN转换 %q 期望 %q，实际得到 %q", tc.input, tc.expected, result)
		}
	}
}

// 测试记录类型转换
func TestGetRRType(t *testing.T) {
	testCases := []struct {
		input    string
		expected uint16
	}{
		{"A", dns.TypeA},
		{"AAAA", dns.TypeAAAA},
		{"CNAME", dns.TypeCNAME},
		{"MX", dns.TypeMX},
		{"NS", dns.TypeNS},
		{"TXT", dns.TypeTXT},
		{"unknown", dns.TypeA}, // 测试默认值
		{"a", dns.TypeA},       // 测试小写
		{"AAAAA", dns.TypeA},   // 测试无效类型
	}

	for _, tc := range testCases {
		result := getRRType(tc.input)
		if result != tc.expected {
			t.Errorf("getRRType(%q) 期望 %d，实际得到 %d", tc.input, tc.expected, result)
		}
	}
}

// 测试IPv6检测
func TestIsIPv6(t *testing.T) {
	testCases := []struct {
		input    string
		expected bool
	}{
		{"2001:4860:4860::8888", true},
		{"8.8.8.8", false},
		{"example.com", false},
		{"fe80::1", true},
		{"192.168.1.1", false},
		{"[2001:4860:4860::8844]", true},
	}

	for _, tc := range testCases {
		result := isIPv6(tc.input)
		if result != tc.expected {
			t.Errorf("isIPv6(%q) 期望 %v，实际得到 %v", tc.input, tc.expected, result)
		}
	}
}

// 测试普通DNS查询（集成测试）
func TestResolveNormal(t *testing.T) {
	// 使用公共DNS服务器进行测试
	tests := []struct {
		domain     string
		recordType string
		dnsServer  string
		shouldErr  bool
	}{
		{"example.com", "A", "8.8.8.8", false},
		{"example.com", "AAAA", "8.8.8.8", false},
		{"example.com", "MX", "1.1.1.1", false},
		{"invalid.invalid", "A", "8.8.8.8", true},           // 无效域名应返回错误
		{"example.com", "A", "2001:4860:4860::8888", false}, // IPv6 DNS服务器
	}

	// 保存原始超时配置并在测试后恢复
	originalTimeout := config.TimeoutSeconds
	config.TimeoutSeconds = 10

	for _, test := range tests {
		t.Run(test.domain+"_"+test.recordType, func(t *testing.T) {
			answers, err := resolveNormal(test.domain, test.recordType, test.dnsServer)

			if test.shouldErr {
				if err == nil {
					t.Error("期望出现错误，但未发生错误")
				}
			} else {
				if err != nil {
					t.Errorf("解析失败: %v", err)
					return
				}
				if len(answers) == 0 {
					t.Error("未返回任何解析结果")
				} else {
					t.Logf("成功解析 %s %s，得到 %d 条记录", test.domain, test.recordType, len(answers))
				}
			}
		})
	}

	// 恢复原始配置
	config.TimeoutSeconds = originalTimeout
}

// 测试DoH查询（集成测试）
func TestResolveDoH(t *testing.T) {
	tests := []struct {
		domain     string
		recordType string
		endpoint   string
		shouldErr  bool
	}{
		{"example.com", "A", "https://cloudflare-dns.com/dns-query", false},
		{"example.com", "AAAA", "https://dns.google/resolve", false},
		{"example.com", "TXT", "https://cloudflare-dns.com/dns-query", false},
		{"invalid.invalid", "A", "https://cloudflare-dns.com/dns-query", true},
	}

	// 保存原始超时配置并在测试后恢复
	originalTimeout := config.TimeoutSeconds
	config.TimeoutSeconds = 10

	for _, test := range tests {
		t.Run(test.domain+"_"+test.recordType, func(t *testing.T) {
			answers, err := resolveDoH(test.domain, test.recordType, test.endpoint)

			if test.shouldErr {
				if err == nil {
					t.Error("期望出现错误，但未发生错误")
				}
			} else {
				if err != nil {
					t.Errorf("DoH解析失败: %v", err)
					return
				}
				if len(answers) == 0 {
					t.Error("未返回任何解析结果")
				} else {
					t.Logf("DoH成功解析 %s %s，得到 %d 条记录", test.domain, test.recordType, len(answers))
				}
			}
		})
	}

	// 恢复原始配置
	config.TimeoutSeconds = originalTimeout
}

// 测试DoT查询（集成测试）
func TestResolveDoT(t *testing.T) {
	tests := []struct {
		domain     string
		recordType string
		dnsServer  string
		shouldErr  bool
	}{
		{"example.com", "A", "1.1.1.1:853", false},    // Cloudflare
		{"example.com", "AAAA", "8.8.8.8:853", false}, // Google
		{"example.com", "NS", "9.9.9.9:853", false},   // Quad9
		{"invalid.invalid", "A", "1.1.1.1:853", true},
		{"example.com", "A", "[2606:4700:4700::1111]:853", false}, // IPv6 DoT服务器
	}

	// 保存原始超时配置并在测试后恢复
	originalTimeout := config.TimeoutSeconds
	config.TimeoutSeconds = 10

	for _, test := range tests {
		t.Run(test.domain+"_"+test.recordType, func(t *testing.T) {
			answers, err := resolveDoT(test.domain, test.recordType, test.dnsServer)

			if test.shouldErr {
				if err == nil {
					t.Error("期望出现错误，但未发生错误")
				}
			} else {
				if err != nil {
					t.Errorf("DoT解析失败: %v", err)
					return
				}
				if len(answers) == 0 {
					t.Error("未返回任何解析结果")
				} else {
					t.Logf("DoT成功解析 %s %s，得到 %d 条记录", test.domain, test.recordType, len(answers))
				}
			}
		})
	}

	// 恢复原始配置
	config.TimeoutSeconds = originalTimeout
}

// 测试TLS连接（专门测试ServerName设置）
func TestTLSConnection(t *testing.T) {
	tests := []struct {
		serverAddr string
		shouldErr  bool
	}{
		{"1.1.1.1:853", false},                // Cloudflare
		{"8.8.8.8:853", false},                // Google
		{"[2606:4700:4700::1111]:853", false}, // Cloudflare IPv6
		{"invalid.example:853", true},         // 无效服务器
	}

	for _, test := range tests {
		t.Run(test.serverAddr, func(t *testing.T) {
			serverName := getServerName(test.serverAddr)

			conn, err := tls.DialWithDialer(&net.Dialer{
				Timeout: 5 * time.Second,
			}, "tcp", test.serverAddr, &tls.Config{
				InsecureSkipVerify: false,
				ServerName:         serverName,
			})

			if test.shouldErr {
				if err == nil {
					t.Error("期望出现错误，但连接成功建立")
					conn.Close()
				}
			} else {
				if err != nil {
					t.Errorf("TLS连接失败: %v (ServerName: %q)", err, serverName)
					return
				}
				t.Logf("TLS连接成功建立 (ServerName: %q)", serverName)
				conn.Close()
			}
		})
	}
}

// 测试配置加载功能
func TestLoadConfig(t *testing.T) {
	// 保存原始配置路径
	originalPath := configPath

	// 测试默认配置文件创建
	configPath = "./test_config.json"
	if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("无法删除测试配置文件: %v", err)
	}

	if err := loadConfig(); err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 验证默认配置是否正确加载
	if config.ListenPort != 5353 {
		t.Errorf("默认端口不正确，期望 5353，实际 %d", config.ListenPort)
	}

	if config.DefaultServer != "8.8.8.8" {
		t.Errorf("默认服务器不正确，期望 8.8.8.8，实际 %s", config.DefaultServer)
	}

	// 清理测试文件
	os.Remove(configPath)

	// 恢复原始配置路径
	configPath = originalPath
}
