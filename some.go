package main

import (
	"encoding/json"
	"fmt"
	"log/slog" // 2026年主流：标准库结构化日志
	"net/http"
)

// UserA 定义数据模型
type UserA struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func main3() {

	// 2. 使用 Go 1.22+ 增强型路由 (Go 1.26 完全体)
	mux := http.NewServeMux()

	// 路由匹配：支持方法(GET)和路径参数({id})
	mux.HandleFunc("GET /users/{id}", getUserHandler)
	mux.HandleFunc("POST /users", createUserHandler)

	slog.Info("服务器启动", "port", 8080)

	// 3. 启动监听
	if err := http.ListenAndServe(":8080", mux); err != nil {
		slog.Error("启动失败", "error", err)
	}
}

// 获取用户（处理路径参数）
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	// 直接从请求中获取路径变量 {id}
	id := r.PathValue("id")

	user := UserA{ID: id, Name: "新手开发者"}

	slog.Info("查询用户", "id", id, "method", r.Method)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// 创建用户（处理 JSON Payload）
func createUserHandler(w http.ResponseWriter, r *http.Request) {
	var u UserA
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, "无效输入", http.StatusBadRequest)
		return
	}

	slog.Info("创建用户成功", "name", u.Name)
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "UserA %s created", u.Name)
}
