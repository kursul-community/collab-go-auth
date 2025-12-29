// Package app configures and runs HTTP Gateway for REST API.
package app

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"go-auth/config"
	"go-auth/gen/auth"
)

// RunGateway - запускает HTTP Gateway сервер для REST API
func RunGateway(cfg *config.Config) error {
	logger := log.Default()

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Создаем gRPC Gateway mux
	mux := runtime.NewServeMux()

	// Настройки для подключения к gRPC серверу
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}

	// Подключаемся к gRPC серверу
	// В Docker gateway и gRPC в одном контейнере, используем localhost
	// Для внешних подключений можно использовать cfg.GRPC.Host
	grpcAddr := fmt.Sprintf("localhost:%d", cfg.GRPC.Port)
	err := auth.RegisterAuthHandlerFromEndpoint(ctx, mux, grpcAddr, opts)
	if err != nil {
		return fmt.Errorf("failed to register gateway: %w", err)
	}

	// Настраиваем CORS middleware
	handler := corsMiddleware(mux)

	// Запускаем HTTP сервер
	httpAddr := fmt.Sprintf(":%d", cfg.HTTP.Port)
	logger.Printf("Starting HTTP Gateway server on port %d\n", cfg.HTTP.Port)
	logger.Printf("REST API available at http://localhost:%d/api/v1/auth/*\n", cfg.HTTP.Port)

	if err := http.ListenAndServe(httpAddr, handler); err != nil {
		return fmt.Errorf("failed to serve HTTP Gateway: %w", err)
	}

	return nil
}

// corsMiddleware - добавляет CORS заголовки для фронтенда
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Устанавливаем CORS заголовки
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Content-Type", "application/json")

		// Обрабатываем preflight запросы
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

