// Package app configures and runs application.
package app

import (
	"context"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"

	"go-auth/config"
	"go-auth/gen/auth"
	"go-auth/internal/adapter/database"
	emailadapter "go-auth/internal/adapter/email"
	redisadapter "go-auth/internal/adapter/redis"
	"go-auth/internal/adapter/token"
	grpcauth "go-auth/internal/controller/grpc/auth"
	tokenrepo "go-auth/internal/repo/token"
	"go-auth/internal/repo/user"
	usecase "go-auth/internal/usecase/auth"
)

// Run - запускает приложение
func Run(cfg *config.Config, devMode bool) {
	// Инициализация дефолтного логгера
	logger := log.Default()

	ctx := context.Background()

	// Подключение к базе данных PostgreSQL
	dbpool, err := database.New(ctx, *cfg)
	if err != nil {
		logger.Fatalf("Unable to create PostgreSQL connection pool: %v", err)
	}
	defer dbpool.Close()
	logger.Printf("PostgreSQL connection established")

	// Подключение к Redis
	redisClient, err := redisadapter.New(ctx, cfg.Redis)
	if err != nil {
		logger.Fatalf("Unable to connect to Redis: %v", err)
	}
	defer redisClient.Close()
	logger.Printf("Redis connection established")

	// Создаем репозитории
	userRepo := user.NewRepository(dbpool)
	tokenRepo := tokenrepo.NewRepository(redisClient)

	// Создаем сервис работы с токенами
	tokenSvc, err := token.New(cfg.Token.Secret, cfg.Token.AccessTTL, cfg.Token.RefreshTTL)
	if err != nil {
		logger.Fatalf("Failed to initialize token service: %v", err)
	}

	// Создаем email сервис для отправки писем
	mailer, err := emailadapter.New(cfg.SMTP)
	if err != nil {
		logger.Fatalf("Failed to initialize email service: %v", err)
	}
	logger.Printf("Email service initialized (SMTP: %s)", cfg.SMTP.Addr())

	// Создаем слой usecase с TTL параметрами
	// Используем дефолтное значение для passwordResetTTL (0 = будет использован DefaultPasswordResetTTL)
	// Используем пустую строку для frontendURL (можно добавить в конфиг позже)
	authUseCase := usecase.NewAuthUseCase(
		userRepo,
		tokenRepo,
		tokenSvc,
		mailer,
		cfg.Token.AccessTTL,
		cfg.Token.RefreshTTL,
		0, // passwordResetTTL - будет использован дефолт
		"", // frontendURL - можно добавить в конфиг позже
	)

	// Создаем gRPC-сервер
	grpcServer := grpc.NewServer(
		grpc.StreamInterceptor(grpcLogStreamInterceptor),
		grpc.UnaryInterceptor(grpcLogUnaryInterceptor),
	)

	// Создаем и регистрируем gRPC-сервис Auth
	authController := grpcauth.NewAuthServer(authUseCase)
	auth.RegisterAuthServer(grpcServer, authController)

	// Слушаем порт gRPC
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPC.Port))
	if err != nil {
		logger.Fatalf("Failed to listen on port %d: %v", cfg.GRPC.Port, err)
	}

	logger.Printf("Starting gRPC server on port %d\n", cfg.GRPC.Port)
	
	// Запускаем gRPC-сервер в горутине
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			logger.Fatalf("Failed to serve gRPC server: %v", err)
		}
	}()

	// Запускаем HTTP Gateway для REST API
	if err := RunGateway(cfg); err != nil {
		logger.Fatalf("Failed to serve HTTP Gateway: %v", err)
	}
}

// Интерсепторы для логирования
func grpcLogStreamInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	logger := log.Default()
	logger.Printf("gRPC Stream called: %s from %s", info.FullMethod, ss.Context().Value("peer").(*peer.Peer).Addr.String())
	return handler(srv, ss)
}

func grpcLogUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	logger := log.Default()
	peerInfo, _ := peer.FromContext(ctx)

	resp, err := handler(ctx, req)

	if err != nil {
		logger.Printf("gRPC Unary response error: %s, method: %s, error: %v", peerInfo.Addr.String(), info.FullMethod, err)
	} else {
		logger.Printf("gRPC Unary response: %s, method: %s, response: %v", peerInfo.Addr.String(), info.FullMethod, resp)
	}

	return resp, err
}
