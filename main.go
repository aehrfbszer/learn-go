package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

func main() {

	mux := http.NewServeMux() // 创建一个新的ServeMux实例

	http.HandleFunc("/", Hello) // 注册处理函数
	http.HandleFunc("/user/login", login)

	mux.HandleFunc("GET /path/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "got path\n")
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

		fmt.Fprintf(w, "v1=%v\n", v1)               // 输出查询参数
		fmt.Fprintf(w, "v2=%q\n", v2)               // 输出表单
		fmt.Fprintf(w, "v3=%+v\n", v3)              // 输出解析后的 JSON
		fmt.Fprintf(w, "v4=%q\n", v4)               // 输出路径参数
		fmt.Fprintf(w, "cookie=%v\n", cookie.Value) // 输出 Cookie
		fmt.Fprintf(w, "auth=%q\n", auth)           // 输出单个 Header
		fmt.Fprintf(w, "headers=%v\n", headers)     // 输出多个同名 Header

		// fmt.Fprintf(w, "handling task with id=%v\n", id)
	})

	go http.ListenAndServe("0.0.0.0:8088", nil)
	go main1()

	// 使用中间件包装
	server := &http.Server{
		Handler: errorHandler(mux),
		Addr:    ":8899", // 设置监听地址和端口
	}
	server.ListenAndServe()

	// http.ListenAndServe("0.0.0.0:8899", mux)
}
