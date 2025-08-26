为了让DNS服务更好地与systemd集成管理，我们需要调整日志输出方式并添加适当的服务配置。systemd推荐使用标准输出/错误流进行日志记录，由journald统一管理。


    
    



与systemd集成的主要修改点：

1. **日志系统适配**：
   - 移除了自定义日志文件配置，改为输出到标准输出(stdout)
   - 日志由systemd的journald统一收集管理
   - 增加日志级别控制，可通过命令行参数调整

2. **服务管理优化**：
   - 移除了后台运行(daemonize)代码，由systemd管理进程生命周期
   - 增加用户/组切换功能，支持降权运行提高安全性
   - 改进信号处理，支持systemd常用信号(SIGHUP, SIGUSR1等)

3. **systemd服务配置**：
   - 提供完整的.service文件，符合systemd服务规范
   - 包含安全增强选项(ProtectHome, ProtectSystem等)
   - 配置了适当的重启策略和资源限制

**使用方法**：

1. 编译并安装服务：
   ```bash
   go build -o dnsresolver dns_service.go
   sudo cp dnsresolver /usr/local/bin/
   ```

2. 安装systemd服务文件：
   ```bash
   sudo cp dnsresolver.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

3. 管理服务：
   ```bash
   # 启动服务
   sudo systemctl start dnsresolver
   
   # 停止服务
   sudo systemctl stop dnsresolver
   
   # 重启服务
   sudo systemctl restart dnsresolver
   
   # 设置开机自启
   sudo systemctl enable dnsresolver
   ```

4. 查看日志：
   ```bash
   # 查看最新日志
   journalctl -u dnsresolver -f
   
   # 查看特定时间段日志
   journalctl -u dnsresolver --since "1 hour ago"
   
   # 查看错误日志
   journalctl -u dnsresolver -p err
   ```

这种集成方式符合Linux系统服务的最佳实践，能够更好地与系统管理工具配合，简化服务的部署、监控和维护工作。