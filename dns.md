我将为您创建一个可以在Linux上作为服务运行的DNS解析器，支持并发处理多个DNS请求。
这个实现将包含服务管理功能（如后台运行、信号处理）和并发请求处理能力。

这个DNS解析服务具有以下特点：

1. **服务特性**：
   - 支持作为Linux服务运行，可后台启动
   - 支持TCP和UDP协议，默认监听5353端口
   - 包含日志记录和PID文件管理
   - 支持优雅关闭（响应SIGINT、SIGTERM等信号）

2. **并发处理**：
   - 每个DNS请求都在独立的goroutine中处理
   - 利用Go的并发模型高效处理大量并发请求
   - 为每个请求设置超时时间，防止资源耗尽

3. **功能支持**：
   - 保留原有的三种查询方式：普通DNS、DoH、DoT
   - 支持IPv4和IPv6的DNS服务器
   - 兼容标准DNS协议，可被普通DNS客户端使用

4. **使用方法**：

   ```bash
   # 直接运行（前台模式）
   go run dns_service.go
   
   # 后台运行
   go run dns_service.go -background
   
   # 自定义监听端口和地址
   go run dns_service.go -addr 0.0.0.0 -port 53
   
   # 指定默认使用DoH查询
   go run dns_service.go -default-query doh
   ```

5. **作为系统服务安装**：
   可以创建systemd服务文件（如`/etc/systemd/system/dnsresolver.service`）：
   ```ini
   [Unit]
   Description=DNS Resolver Service
   After=network.target
   
   [Service]
   ExecStart=/usr/local/bin/dnsresolver -background
   Restart=always
   
   [Install]
   WantedBy=multi-user.target
   ```

这个实现充分利用了Go语言的并发特性，能够高效处理大量并发DNS请求，同时保持了代码的可维护性和扩展性。