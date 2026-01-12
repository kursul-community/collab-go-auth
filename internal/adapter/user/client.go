package user

import (
	"context"
	"fmt"

	pb "go-auth/gen/user"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type Client interface {
	ProfileExists(ctx context.Context, userID string) (bool, error)
}

type client struct {
	userClient pb.UserServiceClient
}

func NewClient(addr string) (Client, error) {
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to user service: %w", err)
	}

	return &client{
		userClient: pb.NewUserServiceClient(conn),
	}, nil
}

func (c *client) ProfileExists(ctx context.Context, userID string) (bool, error) {
	_, err := c.userClient.GetProfile(ctx, &pb.GetProfileRequest{UserId: userID})
	if err != nil {
		st, ok := status.FromError(err)
		if ok && st.Code() == codes.NotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

