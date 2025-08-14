package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

// 定义url路径对应的处理函数
func Hello(w http.ResponseWriter, r *http.Request) {
	fmt.Println("handle Hello") // 后台输出的信息
	fmt.Fprintf(w, "hello")     // 响应请求的数据
}

// 定义url路径对应的处理函数
func login(w http.ResponseWriter, r *http.Request) {
	fmt.Println("handle Hello") // 后台输出的信息
	// fmt.Fprintf(w, "login")            // 响应请求的数据
	io.WriteString(w, "response data") // 也可以使用io包下的方法返回消息
}

type User struct {
	Name  string `json:"name"`
	Age   int    `json:"age"`
	Email string `json:"email"`
}

// 自定义错误类型
type AppError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *AppError) Error() string {
	return e.Message
}

// 中间件：统一错误处理
func errorHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// 处理panic错误
				appErr, ok := err.(*AppError)
				if !ok {
					appErr = &AppError{
						Code:    http.StatusInternalServerError,
						Message: "Internal server error",
					}
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(appErr.Code)
				json.NewEncoder(w).Encode(appErr)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

func localCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 设置 CORS 头
		// 注意cors的Origin不能包含尾部斜杠，否则会导致跨域请求失败
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3001")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// 预检请求缓存时间（1800秒/30分钟）
		w.Header().Set("Access-Control-Max-Age", "1800")

		// 允许携带凭证（如需要）
		// 默认同源是携带的
		// 如果跨域请求需要携带凭证（如 cookies），需要设置 Access-Control-Allow-Credentials 为 true
		// w.Header().Set("Access-Control-Allow-Credentials", "true")

		// 允许前端读取的自定义响应头
		//允许服务器指示那些响应标头可以暴露给浏览器中运行的脚本，以响应跨源请求。
		//默认情况下，仅暴露列入 CORS 白名单的请求标头。
		// 如果想要让客户端可以访问到其他的标头，服务器必须将它们在 Access-Control-Expose-Headers 里面列出来。
		// w.Header().Set("Access-Control-Expose-Headers", "X-Total-Count, X-Pagination")

		// 安全增强头部
		// w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")

		// 处理预检请求,golang的options请求需要手动处理
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// 继续处理实际请求
		next.ServeHTTP(w, r)
	})
}

func staticFiles() http.Handler {
	// 获取当前工作目录
	dir, _ := os.Getwd()
	// 构建静态文件目录的绝对路径
	staticDir := filepath.Join(dir, "static")
	// 确保 public 目录存在
	if _, err := os.Stat(staticDir); os.IsNotExist(err) {
		if err := os.MkdirAll(staticDir, 0755); err != nil {
			log.Fatal(err)
		}
	}

	fs := http.FileServer(http.Dir(staticDir)) // 设置静态文件目录

	return fs
}

func JsonResponse(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

var tempToken int

func main() {

	mux := http.NewServeMux() // 创建一个新的ServeMux实例

	http.HandleFunc("/", Hello) // 注册处理函数
	http.HandleFunc("/user/login", login)

	// 注册路径以斜杠结尾（前缀匹配），但请求路径缺少结尾斜杠
	// 请求 /path1（无结尾斜杠）会被重定向到 /path1/（带斜杠）
	mux.HandleFunc("GET /path1/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "got path1\n")
	})

	//注册路径为精确匹配（无斜杠结尾），但请求路径包含结尾斜杠
	// 请求 /path2/（带斜杠）会被重定向到 /path2（无斜杠）
	mux.HandleFunc("GET /path2", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "got path2\n")
	})

	mux.HandleFunc("/be-expired", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		fmt.Println("Received token:", token, tempToken)
		if token != fmt.Sprintf("Bearer %d", tempToken) {
			http.Error(w, "Token expired", http.StatusUnauthorized)
			return
		}
		tempToken++ // 模拟令牌过期
		fmt.Fprint(w, "Token is valid")
	})

	mux.HandleFunc("POST /refresh-token", func(w http.ResponseWriter, r *http.Request) {
		JsonResponse(w, tempToken)
	})

	mux.HandleFunc("/task/{id}/", func(w http.ResponseWriter, r *http.Request) {
		v1 := r.URL.Query()["AA"] // 获取查询参数

		// FormValue：
		// 1.优先尝试取application/x-www-form-urlencoded类型的body（即js的body是URLSearchParams），
		// 2.然后尝试取url的query（即js中url的❓之后拼接URLSearchParams.toString），
		// 3.最后取multipart/form-data的body(即js传的body是FormData，这有问题吧，file类型不支持吧，怎么转成字符？)
		// 注意：最后的结果是单个字符串，用这个方法无法获取同名键传过来的数组
		v2 := r.FormValue("BB")

		var v3 User
		// 直接从请求体解析 JSON（自动关闭请求体）
		if err := json.NewDecoder(r.Body).Decode(&v3); err != nil {
			// http.Error(w, "解析 JSON 失败: "+err.Error(), http.StatusBadRequest)
			// return
			panic(&AppError{
				Code:    http.StatusBadRequest,
				Message: "解析 JSON 失败: " + err.Error(),
			})
		}

		// 路径不全进不来，所以pathvalue一般来说是必定有值的
		v4 := r.PathValue("id") // 获取路径参数

		cookie, _ := r.Cookie("csrfToken")

		// 获取单个 Header
		auth := r.Header.Get("Authorization")
		// 获取多个同名 Header（返回字符串切片）
		headers := r.Header.Values("X-Custom-Header")

		fmt.Fprintf(w, "v1=%v\n", v1)           // 输出查询参数
		fmt.Fprintf(w, "v2=%q\n", v2)           // 输出表单
		fmt.Fprintf(w, "v3=%+v\n", v3)          // 输出解析后的 JSON
		fmt.Fprintf(w, "v4=%q\n", v4)           // 输出路径参数
		fmt.Fprintf(w, "cookie=%v\n", cookie)   // 输出 Cookie
		fmt.Fprintf(w, "auth=%q\n", auth)       // 输出单个 Header
		fmt.Fprintf(w, "headers=%v\n", headers) // 输出多个同名 Header

		// fmt.Fprintf(w, "handling task with id=%v\n", id)
	})
	// golang不支持在函数里定义函数，只能使用匿名函数
	// 可以立即执行匿名函数；或者绑定给一个变量，后续再执行
	qq := func(a string) {
		fmt.Println("qq:", a)
	}
	qq("test")
	// 创建用户相关的子路由器
	userMux := http.NewServeMux()
	userMux.HandleFunc("/all", getUser) // 处理GET /users/

	// 将子路由器注册到主路由器上
	// golang的路由以斜杠结尾时，表示匹配该路径下的所有子路径
	// 例如：/users/ 会匹配 /users/all、/users/123
	// 如果不以斜杠结尾，则只匹配精确路径
	// 例如：/users 会匹配 /users，但不会匹配 /users/all
	mux.Handle("/users/", http.StripPrefix("/users", userMux))
	mux.Handle("GET /static/", http.StripPrefix("/static", staticFiles())) // 静态文件处理

	go http.ListenAndServe("0.0.0.0:8088", nil)
	go main1()

	p := http.NewCrossOriginProtection()
	p.AddTrustedOrigin("http://localhost:3001") // 添加受信任的源
	// 使用中间件包装
	server := &http.Server{
		Handler: p.Handler(localCors(errorHandler(mux))),
		Addr:    ":8899", // 设置监听地址和端口
	}
	server.ListenAndServe()

	// http.ListenAndServe("0.0.0.0:8899", mux)
}

func getUser(w http.ResponseWriter, r *http.Request) {
	// 模拟获取用户信息
	user := [2]User{
		{
			Name:  "John Doe",
			Age:   30,
			Email: "aaa@example.com",
		},
		{
			Name:  "Jane Smith",
			Age:   25,
			Email: "sa",
		},
	}
	JsonResponse(w, user) // 使用自定义的 JSON 响应函数
}
