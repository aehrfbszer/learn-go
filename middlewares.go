package main

import (
	"log"
	"net/http"
	"time"
)

// 日志中间件
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// 包装 ResponseWriter 以捕获状态码
		lw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// 传递给下一个处理器
		next.ServeHTTP(lw, r)

		// 记录日志
		log.Printf(
			"method=%s path=%s status=%d duration=%s",
			r.Method,
			r.URL.Path,
			lw.statusCode,
			time.Since(start),
		)
	})
}

// 自定义 ResponseWriter 以捕获状态码
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

// 认证中间件
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 从请求头获取认证信息
		token := r.Header.Get("Authorization")

		// 验证 token（简化示例）
		if token != "valid-token" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// 验证通过，继续处理请求
		next.ServeHTTP(w, r)
	})
}

// CORS 中间件
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 设置 CORS 头
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")

		// 处理预检请求
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// 继续处理实际请求
		next.ServeHTTP(w, r)
	})
}

// 恢复中间件（处理 Panic）
func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// 记录 panic 信息
				log.Printf("Panic: %v", err)

				// 返回 500 错误
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// 带参数的日志中间件
func loggingMiddlewareWithFormat(format string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 自定义日志格式
			log.Printf(format, r.Method, r.URL.Path)

			next.ServeHTTP(w, r)
		})
	}
}

// 组合多个中间件
func chainMiddlewares(handler http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}

func main1() {
	mux := http.NewServeMux()

	// 公共路由
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})

	// 私有路由（需要认证）
	mux.Handle("/private", authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("This is a private route"))
	})))

	// 模拟 panic 的路由
	mux.HandleFunc("/panic", func(w http.ResponseWriter, r *http.Request) {
		panic("oops! something went wrong")
	})

	// 按顺序应用中间件
	server := &http.Server{
		Handler: chainMiddlewares(
			mux,
			recoveryMiddleware,
			loggingMiddleware,
			corsMiddleware,
			loggingMiddlewareWithFormat("[%s] %s"),
		),
		Addr: ":8080",
	}

	log.Println("Server started on :8080")
	server.ListenAndServe()
}
