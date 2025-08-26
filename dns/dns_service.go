package dns

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// 配置结构定义
type Config struct {
	ListenAddr     string `json:"listen_addr"`
	ListenPort     int    `json:"listen_port"`
	Protocol       string `json:"protocol"` // "tcp", "udp" or "both"
	LogLevel       string `json:"log_level"`
	DefaultQuery   string `json:"default_query"`  // 默认查询类型
	DefaultServer  string `json:"default_server"` // 默认DNS服务器
	DoHEndpoint    string `json:"doh_endpoint"`
	Timeout        int    `json:"timeout_seconds"`
	MaxConnections int    `json:"max_connections"`
}

// DNS查询类型
const (
	QueryTypeNormal = "normal"
	QueryTypeDoH    = "doh"
	QueryTypeDoT    = "dot"
)

// DNS记录类型
const (
	RecordTypeA     = "A"
	RecordTypeAAAA  = "AAAA"
	RecordTypeCNAME = "CNAME"
	RecordTypeMX    = "MX"
	RecordTypeNS    = "NS"
	RecordTypeTXT   = "TXT"
)

var config Config
var logger *log.Logger

func main() {
	// 解析命令行参数（主要用于指定配置文件路径）
	configPath := flag.String("config", "/etc/dnsresolver/config.json", "配置文件路径")
	flag.Parse()

	// 加载配置文件
	if err := loadConfig(*configPath); err != nil {
		fmt.Printf("加载配置文件失败: %v\n", err)
		os.Exit(1)
	}

	// 初始化日志
	initLogger()

	logger.Printf("DNS解析服务启动，监听 %s:%d (%s)",
		config.ListenAddr, config.ListenPort, config.Protocol)

	// 设置信号处理
	setupSignalHandler()

	// 启动服务器
	startServer()
}

// 加载JSON配置文件
func loadConfig(path string) error {
	// 设置默认值
	config = Config{
		ListenAddr:     "0.0.0.0",
		ListenPort:     5353,
		Protocol:       "both",
		LogLevel:       "info",
		DefaultQuery:   QueryTypeNormal,
		DefaultServer:  "8.8.8.8",
		DoHEndpoint:    "https://cloudflare-dns.com/dns-query",
		Timeout:        5,
		MaxConnections: 1000,
	}

	// 检查文件是否存在
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// 配置文件不存在，创建默认配置
		if err := createDefaultConfig(path); err != nil {
			return fmt.Errorf("配置文件不存在且无法创建默认配置: %v", err)
		}
		logger.Printf("使用默认配置，配置文件已创建在 %s", path)
		return nil
	}

	// 读取配置文件
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %v", err)
	}

	// 解析JSON
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 验证配置
	return validateConfig()
}

// 创建默认配置文件
func createDefaultConfig(path string) error {
	// 创建目录
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// 序列化默认配置
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	// 写入文件
	return os.WriteFile(path, data, 0644)
}

// 验证配置
func validateConfig() error {
	if config.ListenPort < 1 || config.ListenPort > 65535 {
		return fmt.Errorf("无效的端口号: %d", config.ListenPort)
	}

	if config.Protocol != "tcp" && config.Protocol != "udp" && config.Protocol != "both" {
		return fmt.Errorf("无效的协议类型: %s", config.Protocol)
	}

	if config.DefaultQuery != QueryTypeNormal && config.DefaultQuery != QueryTypeDoH && config.DefaultQuery != QueryTypeDoT {
		return fmt.Errorf("无效的默认查询类型: %s", config.DefaultQuery)
	}

	if config.Timeout <= 0 {
		return fmt.Errorf("超时时间必须大于0: %d", config.Timeout)
	}

	if config.MaxConnections <= 0 {
		return fmt.Errorf("最大连接数必须大于0: %d", config.MaxConnections)
	}

	return nil
}

// 初始化日志
func initLogger() {
	var logOutput io.Writer = os.Stdout

	logger = log.New(logOutput, "", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)
}

// 设置信号处理
func setupSignalHandler() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		sig := <-sigChan
		logger.Printf("收到信号 %s，正在关闭服务...", sig)

		// SIGHUP信号处理 - 重新加载配置
		if sig == syscall.SIGHUP {
			logger.Println("重新加载配置...")
			if err := loadConfig(flag.Lookup("config").Value.String()); err != nil {
				logger.Printf("重新加载配置失败: %v", err)
			} else {
				logger.Println("配置已重新加载")
			}
			return
		}

		os.Exit(0)
	}()
}

// 启动服务器
func startServer() {
	// 注册DNS处理函数
	dns.HandleFunc(".", handleDNSRequest)

	// 启动UDP服务器
	if config.Protocol == "udp" || config.Protocol == "both" {
		go func() {
			server := &dns.Server{
				Addr:    fmt.Sprintf("%s:%d", config.ListenAddr, config.ListenPort),
				Net:     "udp",
				Handler: dns.DefaultServeMux,
				UDPSize: 4096,
			}

			logger.Printf("UDP服务器启动在 %s", server.Addr)
			if err := server.ListenAndServe(); err != nil {
				logger.Fatalf("UDP服务器失败: %v", err)
			}
		}()
	}

	// 启动TCP服务器
	if config.Protocol == "tcp" || config.Protocol == "both" {
		go func() {
			server := &dns.Server{
				Addr:    fmt.Sprintf("%s:%d", config.ListenAddr, config.ListenPort),
				Net:     "tcp",
				Handler: dns.DefaultServeMux,
			}

			logger.Printf("TCP服务器启动在 %s", server.Addr)
			if err := server.ListenAndServe(); err != nil {
				logger.Fatalf("TCP服务器失败: %v", err)
			}
		}()
	}

	// 保持主进程运行
	select {}
}

// 处理DNS请求
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	// 每个请求在单独的goroutine中处理，实现并发
	go func() {
		startTime := time.Now()
		clientIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())

		// 记录请求信息
		var domain string
		var qtype string
		if len(r.Question) > 0 {
			domain = r.Question[0].Name
			qtype = dns.TypeToString[r.Question[0].Qtype]
			logger.Printf("收到请求: %s %s 来自 %s", domain, qtype, clientIP)
		}

		// 创建响应
		m := new(dns.Msg)
		m.SetReply(r)
		m.Compress = false

		// 处理请求
		if len(r.Question) == 0 {
			m.Rcode = dns.RcodeFormatError
		} else {
			// 调用解析函数获取结果
			answers, err := resolveDomain(
				strings.TrimSuffix(r.Question[0].Name, "."),
				dns.TypeToString[r.Question[0].Qtype],
				config.DefaultQuery,
				config.DefaultServer,
				config.DoHEndpoint,
			)

			if err != nil {
				logger.Printf("解析错误: %v", err)
				m.Rcode = dns.RcodeServerFailure
			} else {
				m.Answer = answers
			}
		}

		// 发送响应
		if err := w.WriteMsg(m); err != nil {
			logger.Printf("发送响应失败: %v", err)
		}

		// 记录处理时间
		logger.Printf("处理完成: %s %s 耗时 %v", domain, qtype, time.Since(startTime))
	}()
}

// 解析域名（核心解析函数）
func resolveDomain(domain, recordType, queryType, dnsServer, dohEndpoint string) ([]dns.RR, error) {
	switch queryType {
	case QueryTypeNormal:
		return resolveNormal(domain, recordType, dnsServer)
	case QueryTypeDoH:
		return resolveDoH(domain, recordType, dohEndpoint)
	case QueryTypeDoT:
		return resolveDoT(domain, recordType, dnsServer)
	default:
		return resolveNormal(domain, recordType, dnsServer)
	}
}

// 检查是否为IPv6地址
func isIPv6(address string) bool {
	return strings.Count(address, ":") >= 2
}

// 普通DNS查询
func resolveNormal(domain, recordType, dnsServer string) ([]dns.RR, error) {
	// 处理服务器地址
	formattedServer := dnsServer
	if !strings.Contains(dnsServer, ":") {
		formattedServer += ":53"
	} else if isIPv6(dnsServer) && !strings.HasPrefix(dnsServer, "[") {
		formattedServer = "[" + dnsServer + "]:53"
	}

	// 创建DNS客户端
	c := dns.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
	}
	msg := dns.Msg{}
	msg.SetQuestion(dns.Fqdn(domain), getRRType(recordType))
	msg.RecursionDesired = true

	// 发送查询
	r, _, err := c.Exchange(&msg, formattedServer)
	if err != nil {
		return nil, err
	}

	// 检查是否有错误
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("查询返回错误代码: %d", r.Rcode)
	}

	return r.Answer, nil
}

// DoH (DNS over HTTPS) 查询
func resolveDoH(domain, recordType, dohEndpoint string) ([]dns.RR, error) {
	// 创建DNS消息
	msg := dns.Msg{}
	msg.SetQuestion(dns.Fqdn(domain), getRRType(recordType))
	msg.RecursionDesired = true

	// 序列化消息
	_, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	// 构建查询URL
	url := fmt.Sprintf("%s?name=%s&type=%s", dohEndpoint, dns.Fqdn(domain), recordType)

	// 发送HTTPS请求
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 解析响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// 解析JSON响应
	var dohResponse map[string]any
	if err := json.Unmarshal(body, &dohResponse); err != nil {
		return nil, err
	}

	// 检查错误
	if status, ok := dohResponse["Status"].(float64); ok && status != 0 {
		return nil, fmt.Errorf("DoH查询返回错误: 状态码 %d", int(status))
	}

	// 转换为dns.RR格式
	var answers []dns.RR
	if answerList, ok := dohResponse["Answer"].([]interface{}); ok {
		for _, ans := range answerList {
			answer := ans.(map[string]interface{})

			rrType, _ := answer["type"].(float64)
			rrName := answer["name"].(string)
			rrData := answer["data"].(string)
			rrTTL := uint32(answer["TTL"].(float64))

			// 根据类型创建相应的RR记录
			var rr dns.RR
			switch uint16(rrType) {
			case dns.TypeA:
				rr, _ = dns.NewRR(fmt.Sprintf("%s %d IN A %s", rrName, rrTTL, rrData))
			case dns.TypeAAAA:
				rr, _ = dns.NewRR(fmt.Sprintf("%s %d IN AAAA %s", rrName, rrTTL, rrData))
			case dns.TypeCNAME:
				rr, _ = dns.NewRR(fmt.Sprintf("%s %d IN CNAME %s", rrName, rrTTL, rrData))
			case dns.TypeMX:
				// MX记录格式特殊，需要解析优先级
				mxParts := strings.Split(rrData, " ")
				if len(mxParts) == 2 {
					pref, _ := strconv.Atoi(mxParts[0])
					rr, _ = dns.NewRR(fmt.Sprintf("%s %d IN MX %d %s", rrName, rrTTL, pref, mxParts[1]))
				}
			case dns.TypeNS:
				rr, _ = dns.NewRR(fmt.Sprintf("%s %d IN NS %s", rrName, rrTTL, rrData))
			case dns.TypeTXT:
				rr, _ = dns.NewRR(fmt.Sprintf("%s %d IN TXT %s", rrName, rrTTL, rrData))
			}

			if rr != nil {
				answers = append(answers, rr)
			}
		}
	}

	return answers, nil
}

// DoT (DNS over TLS) 查询
func resolveDoT(domain, recordType, dnsServer string) ([]dns.RR, error) {
	// 处理服务器地址
	formattedServer := dnsServer
	if !strings.Contains(dnsServer, ":") {
		formattedServer += ":853"
	} else if isIPv6(dnsServer) && !strings.HasPrefix(dnsServer, "[") {
		formattedServer = "[" + dnsServer + "]:853"
	}

	// 创建TLS连接
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Duration(config.Timeout) * time.Second},
		"tcp", formattedServer, &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         strings.Split(formattedServer, ":")[0],
		})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 创建DNS消息
	msg := dns.Msg{}
	msg.SetQuestion(dns.Fqdn(domain), getRRType(recordType))
	msg.RecursionDesired = true

	// 发送DNS查询
	buf, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	// 前两个字节是消息长度
	length := []byte{byte(len(buf) >> 8), byte(len(buf) & 0xff)}
	_, err = conn.Write(append(length, buf...))
	if err != nil {
		return nil, err
	}

	// 读取响应
	respLength := make([]byte, 2)
	_, err = conn.Read(respLength)
	if err != nil {
		return nil, err
	}

	respBuf := make([]byte, int(respLength[0])<<8|int(respLength[1]))
	_, err = conn.Read(respBuf)
	if err != nil {
		return nil, err
	}

	// 解析响应
	var response dns.Msg
	if err := response.Unpack(respBuf); err != nil {
		return nil, err
	}

	// 检查是否有错误
	if response.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DoT查询返回错误代码: %d", response.Rcode)
	}

	return response.Answer, nil
}

// 转换记录类型字符串为dns包中的常量
func getRRType(recordType string) uint16 {
	switch strings.ToUpper(recordType) {
	case RecordTypeA:
		return dns.TypeA
	case RecordTypeAAAA:
		return dns.TypeAAAA
	case RecordTypeCNAME:
		return dns.TypeCNAME
	case RecordTypeMX:
		return dns.TypeMX
	case RecordTypeNS:
		return dns.TypeNS
	case RecordTypeTXT:
		return dns.TypeTXT
	default:
		return dns.TypeA // 默认查询A记录
	}
}
