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

// 服务配置
type ServiceConfig struct {
	ListenAddr    string
	ListenPort    int
	Protocol      string // "tcp", "udp" or "both"
	User          string // 运行服务的用户
	Group         string // 运行服务的组
	PidFile       string
	DefaultQuery  string // 默认查询类型
	DefaultServer string // 默认DNS服务器
	DoHEndpoint   string
	LogLevel      string // 日志级别: debug, info, warn, error
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

var config ServiceConfig
var logger *log.Logger

func main() {
	// 解析命令行参数
	parseFlags()

	// 初始化日志 - 输出到stdout/stderr，由systemd journal捕获
	initLogger()

	// 切换用户/组（如果配置）
	if err := dropPrivileges(); err != nil {
		logger.Fatalf("无法切换用户/组: %v", err)
	}

	// 写入PID文件
	if config.PidFile != "" {
		if err := writePidFile(config.PidFile); err != nil {
			logger.Fatalf("无法写入PID文件: %v", err)
		}
		defer os.Remove(config.PidFile)
	}

	// 设置信号处理
	setupSignalHandler()

	logger.Printf("DNS解析服务启动，监听 %s:%d (%s)",
		config.ListenAddr, config.ListenPort, config.Protocol)

	// 启动服务器
	startServer()
}

// 解析命令行参数
func parseFlags() {
	config = ServiceConfig{
		ListenAddr:    "0.0.0.0",
		ListenPort:    5353,
		Protocol:      "both",
		User:          "",
		Group:         "",
		PidFile:       "/run/dnsresolver.pid", // 符合FHS标准的位置
		DefaultQuery:  QueryTypeNormal,
		DefaultServer: "8.8.8.8",
		DoHEndpoint:   "https://cloudflare-dns.com/dns-query",
		LogLevel:      "info",
	}

	flag.StringVar(&config.ListenAddr, "addr", config.ListenAddr, "监听地址")
	flag.IntVar(&config.ListenPort, "port", config.ListenPort, "监听端口")
	flag.StringVar(&config.Protocol, "proto", config.Protocol, "协议类型 (tcp, udp, both)")
	flag.StringVar(&config.User, "user", config.User, "运行服务的用户")
	flag.StringVar(&config.Group, "group", config.Group, "运行服务的组")
	flag.StringVar(&config.PidFile, "pid", config.PidFile, "PID文件路径")
	flag.StringVar(&config.DefaultQuery, "default-query", config.DefaultQuery, "默认查询类型")
	flag.StringVar(&config.DefaultServer, "default-server", config.DefaultServer, "默认DNS服务器")
	flag.StringVar(&config.DoHEndpoint, "doh-endpoint", config.DoHEndpoint, "默认DoH端点")
	flag.StringVar(&config.LogLevel, "loglevel", config.LogLevel, "日志级别 (debug, info, warn, error)")

	flag.Parse()
}

// 初始化日志 - 适配systemd journal
func initLogger() {
	// 输出到stdout，由systemd捕获
	logOutput := os.Stdout

	// 日志格式：包含时间和文件名，便于journald处理
	logger = log.New(logOutput, "", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)
}

// 切换到非root用户运行
func dropPrivileges() error {
	if config.User == "" && config.Group == "" {
		return nil
	}

	// 实现用户/组切换逻辑
	// ... (省略具体实现，根据系统API处理)

	return nil
}

// 写入PID文件
func writePidFile(path string) error {
	// 确保PID目录存在
	pidDir := filepath.Dir(path)
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		return err
	}

	pid := os.Getpid()
	content := []byte(fmt.Sprintf("%d\n", pid))
	return os.WriteFile(path, content, 0644)
}

// 设置信号处理 - 适配systemd信号
func setupSignalHandler() {
	sigChan := make(chan os.Signal, 1)
	// 处理systemd常用信号
	signal.Notify(sigChan,
		syscall.SIGINT,  // 中断信号
		syscall.SIGTERM, // 终止信号
		syscall.SIGHUP,  // 重载配置信号
		syscall.SIGUSR1, // 用户自定义信号1，可用于日志轮转
		syscall.SIGUSR2) // 用户自定义信号2

	go func() {
		for sig := range sigChan {
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				logger.Printf("收到终止信号 %s，正在关闭服务...", sig)
				// 清理资源
				os.Exit(0)
			case syscall.SIGHUP:
				logger.Printf("收到重载信号 %s，重新加载配置...", sig)
				// 实现配置重载逻辑
			case syscall.SIGUSR1:
				logger.Printf("收到日志轮转信号 %s", sig)
				// 实现日志轮转逻辑
			}
		}
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
			if config.LogLevel == "debug" || config.LogLevel == "info" {
				logger.Printf("收到请求: %s %s 来自 %s", domain, qtype, clientIP)
			}
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

		// 记录处理时间（调试级别）
		if config.LogLevel == "debug" {
			logger.Printf("处理完成: %s %s 耗时 %v", domain, qtype, time.Since(startTime))
		}
	}()
}

// 以下是核心解析函数，与之前版本基本相同，省略...
func resolveDomain(domain, recordType, queryType, dnsServer, dohEndpoint string) ([]dns.RR, error) {
	// ... 实现代码不变 ...
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

func isIPv6(address string) bool {
	return strings.Count(address, ":") >= 2
}

func resolveNormal(domain, recordType, dnsServer string) ([]dns.RR, error) {
	// ... 实现代码不变 ...
	formattedServer := dnsServer
	if !strings.Contains(dnsServer, ":") {
		formattedServer += ":53"
	} else if isIPv6(dnsServer) && !strings.HasPrefix(dnsServer, "[") {
		formattedServer = "[" + dnsServer + "]:53"
	}

	c := dns.Client{
		Timeout: 5 * time.Second,
	}
	msg := dns.Msg{}
	msg.SetQuestion(dns.Fqdn(domain), getRRType(recordType))
	msg.RecursionDesired = true

	r, _, err := c.Exchange(&msg, formattedServer)
	if err != nil {
		return nil, err
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("查询返回错误代码: %d", r.Rcode)
	}

	return r.Answer, nil
}

func resolveDoH(domain, recordType, dohEndpoint string) ([]dns.RR, error) {
	// ... 实现代码不变 ...
	msg := dns.Msg{}
	msg.SetQuestion(dns.Fqdn(domain), getRRType(recordType))
	msg.RecursionDesired = true

	buf, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s?name=%s&type=%s", dohEndpoint, dns.Fqdn(domain), recordType)

	client := &http.Client{
		Timeout: 10 * time.Second,
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var dohResponse map[string]interface{}
	if err := json.Unmarshal(body, &dohResponse); err != nil {
		return nil, err
	}

	if status, ok := dohResponse["Status"].(float64); ok && status != 0 {
		return nil, fmt.Errorf("DoH查询返回错误: 状态码 %d", int(status))
	}

	var answers []dns.RR
	if answerList, ok := dohResponse["Answer"].([]interface{}); ok {
		for _, ans := range answerList {
			answer := ans.(map[string]interface{})

			rrType, _ := answer["type"].(float64)
			rrName := answer["name"].(string)
			rrData := answer["data"].(string)
			rrTTL := uint32(answer["TTL"].(float64))

			var rr dns.RR
			switch uint16(rrType) {
			case dns.TypeA:
				rr, _ = dns.NewRR(fmt.Sprintf("%s %d IN A %s", rrName, rrTTL, rrData))
			case dns.TypeAAAA:
				rr, _ = dns.NewRR(fmt.Sprintf("%s %d IN AAAA %s", rrName, rrTTL, rrData))
			case dns.TypeCNAME:
				rr, _ = dns.NewRR(fmt.Sprintf("%s %d IN CNAME %s", rrName, rrTTL, rrData))
			case dns.TypeMX:
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

func resolveDoT(domain, recordType, dnsServer string) ([]dns.RR, error) {
	// ... 实现代码不变 ...
	formattedServer := dnsServer
	if !strings.Contains(dnsServer, ":") {
		formattedServer += ":853"
	} else if isIPv6(dnsServer) && !strings.HasPrefix(dnsServer, "[") {
		formattedServer = "[" + dnsServer + "]:853"
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second},
		"tcp", formattedServer, &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         strings.Split(formattedServer, ":")[0],
		})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	msg := dns.Msg{}
	msg.SetQuestion(dns.Fqdn(domain), getRRType(recordType))
	msg.RecursionDesired = true

	buf, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	length := []byte{byte(len(buf) >> 8), byte(len(buf) & 0xff)}
	_, err = conn.Write(append(length, buf...))
	if err != nil {
		return nil, err
	}

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

	var response dns.Msg
	if err := response.Unpack(respBuf); err != nil {
		return nil, err
	}

	if response.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DoT查询返回错误代码: %d", response.Rcode)
	}

	return response.Answer, nil
}

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
		return dns.TypeA
	}
}
