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

func localCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 设置 CORS 头
		// 注意cors的Origin不能包含尾部斜杠，否则会导致跨域请求失败
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3001")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")

		// 处理预检请求,golang的options请求需要手动处理
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// 继续处理实际请求
		next.ServeHTTP(w, r)
	})
}

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

	go http.ListenAndServe("0.0.0.0:8088", nil)
	go main1()

	// 使用中间件包装
	server := &http.Server{
		Handler: localCors(errorHandler(mux)),
		Addr:    ":8899", // 设置监听地址和端口
	}
	server.ListenAndServe()

	// http.ListenAndServe("0.0.0.0:8899", mux)
}

func getUser(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Getting user\n")
}
