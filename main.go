package main

import (
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

func main() {

	mux := http.NewServeMux() // 创建一个新的ServeMux实例

	http.HandleFunc("/", Hello) // 注册处理函数
	http.HandleFunc("/user/login", login)

	mux.HandleFunc("GET /path/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "got path\n")
	})
	mux.HandleFunc("/task/{id}/", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		fmt.Fprintf(w, "handling task with id=%v\n", id)
	})

	go http.ListenAndServe("0.0.0.0:8088", nil)
	http.ListenAndServe("0.0.0.0:8899", mux) // 启动HTTP服务器，监听8088端口和8899端口
}
