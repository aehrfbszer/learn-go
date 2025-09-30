package compression

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"strings"
)

// Config 压缩配置结构体，支持自定义压缩参数
type Config struct {
	Level        int      // 压缩级别(1-9)
	MinSize      int      // 最小压缩尺寸(字节)
	IncludeMIMEs []string // 需要压缩的MIME类型
}

// Option 配置选项模式，用于灵活设置压缩参数
type Option func(*Config)

// WithLevel 设置压缩级别(1-9)
func WithLevel(level int) Option {
	return func(c *Config) {
		if level >= 1 && level <= 9 {
			c.Level = level
		}
	}
}

// WithMinSize 设置最小压缩尺寸(字节)
func WithMinSize(size int) Option {
	return func(c *Config) {
		if size > 0 {
			c.MinSize = size
		}
	}
}

// WithIncludeMIMEs 添加需要压缩的MIME类型
func WithIncludeMIMEs(mimes ...string) Option {
	return func(c *Config) {
		c.IncludeMIMEs = append(c.IncludeMIMEs, mimes...)
	}
}

// 默认配置，覆盖大多数常见场景
var defaultConfig = Config{
	Level:   gzip.DefaultCompression,
	MinSize: 256,
	IncludeMIMEs: []string{
		"text/plain", "text/html", "text/css", "text/javascript",
		"application/json", "application/javascript", "application/xml",
	},
}

// responseCache 响应缓存结构体，私有字段增强封装性
type responseCache struct {
	statusCode int           // 响应状态码
	headers    http.Header   // 响应头
	body       *bytes.Buffer // 响应体缓存
}

// newResponseCache 创建响应缓存实例，确保初始化安全
func newResponseCache() *responseCache {
	return &responseCache{
		statusCode: http.StatusOK,     // 默认200状态码
		headers:    make(http.Header), // 预初始化Header避免nil
		body:       &bytes.Buffer{},   // 预初始化缓冲区
	}
}

// 缓存访问方法，避免直接操作字段
func (c *responseCache) StatusCode() int {
	return c.statusCode
}

func (c *responseCache) Headers() http.Header {
	return c.headers
}

func (c *responseCache) Body() []byte {
	return c.body.Bytes()
}

func (c *responseCache) BodyLen() int {
	return c.body.Len()
}

func (c *responseCache) SetStatusCode(code int) {
	c.statusCode = code
}

func (c *responseCache) WriteBody(data []byte) (int, error) {
	return c.body.Write(data)
}

// GzipMiddleware 压缩中间件入口
func GzipMiddleware(next http.Handler, opts ...Option) http.Handler {
	// 合并配置
	cfg := defaultConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	// 预构建MIME类型映射，提高查找效率
	mimeMap := make(map[string]struct{}, len(cfg.IncludeMIMEs))
	for _, mime := range cfg.IncludeMIMEs {
		mimeMap[mime] = struct{}{}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 客户端不支持gzip则直接放行
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}

		// 捕获响应数据
		cache := newResponseCache()
		captureResponse(cache, next, r)

		// 判断是否需要压缩
		if !shouldCompress(cache, &cfg, mimeMap) {
			writeOriginalResponse(w, cache)
			return
		}

		// 压缩并写入响应
		writeCompressedResponse(w, cache, cfg.Level)
	})
}

// captureResponse 捕获处理器响应到缓存
func captureResponse(cache *responseCache, handler http.Handler, r *http.Request) {
	handler.ServeHTTP(&cacheWriter{cache: cache}, r)
}

// cacheWriter 实现http.ResponseWriter接口，用于捕获响应
type cacheWriter struct {
	cache *responseCache
}

func (w *cacheWriter) Header() http.Header {
	return w.cache.Headers()
}

func (w *cacheWriter) WriteHeader(code int) {
	w.cache.SetStatusCode(code)
}

func (w *cacheWriter) Write(data []byte) (int, error) {
	return w.cache.WriteBody(data)
}

// shouldCompress 判断是否需要压缩
func shouldCompress(cache *responseCache, cfg *Config, mimeMap map[string]struct{}) bool {
	// 排除无需压缩的状态码
	status := cache.StatusCode()
	if status < 200 || status == 204 || status == 304 {
		return false
	}

	// 数据大小未达阈值
	if cache.BodyLen() < cfg.MinSize {
		return false
	}

	// MIME类型不在压缩列表
	contentType := strings.TrimSpace(strings.Split(cache.Headers().Get("Content-Type"), ";")[0])
	_, ok := mimeMap[contentType]
	return ok
}

// writeOriginalResponse 写入原始未压缩响应
func writeOriginalResponse(w http.ResponseWriter, cache *responseCache) {
	copyHeaders(w.Header(), cache.Headers())
	w.WriteHeader(cache.StatusCode())
	w.Write(cache.Body())
}

// writeCompressedResponse 压缩并写入响应
func writeCompressedResponse(w http.ResponseWriter, cache *responseCache, level int) {
	// 压缩数据
	compressedData, err := gzipCompress(cache.Body(), level)
	if err != nil {
		http.Error(w, "压缩失败", http.StatusInternalServerError)
		return
	}

	// 写入压缩响应
	copyHeaders(w.Header(), cache.Headers())
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Del("Content-Length")
	w.Header().Set("Vary", "Accept-Encoding")
	w.WriteHeader(cache.StatusCode())
	w.Write(compressedData)
}

// gzipCompress 执行gzip压缩
func gzipCompress(data []byte, level int) ([]byte, error) {
	buf := &bytes.Buffer{}
	gz, err := gzip.NewWriterLevel(buf, level)
	if err != nil {
		return nil, err
	}

	if _, err := gz.Write(data); err != nil {
		gz.Close() // 确保错误时关闭资源
		return nil, err
	}

	if err := gz.Close(); err != nil { // 必须关闭才能完成压缩
		return nil, err
	}

	return buf.Bytes(), nil
}

// copyHeaders 高效复制响应头
func copyHeaders(dst, src http.Header) {
	for k, v := range src {
		dst[k] = append(dst[k][:0], v...) // 先清空目标再复制，避免重复
	}
}
