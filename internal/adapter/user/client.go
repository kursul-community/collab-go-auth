package user

import (
	"context"
	"fmt"

	pb "go-auth/gen/user"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type Client interface {
	ProfileExists(ctx context.Context, userID string) (bool, error)
	UpdateGitURL(ctx context.Context, userID, gitURL, accessToken string) error
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
	resp, err := c.userClient.GetProfileByID(ctx, &pb.GetProfileByIDRequest{UserId: userID})
	if err != nil {
		st, ok := status.FromError(err)
		if ok && st.Code() == codes.NotFound {
			return false, nil
		}
		return false, err
	}

	profile := resp.GetProfile()
	if profile == nil {
		return false, nil
	}

	// Профиль существует, если user-service вернул запись, независимо от заполненности.
	return true, nil
}

func (c *client) UpdateGitURL(ctx context.Context, userID, gitURL, accessToken string) error {
	if accessToken != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+accessToken)
	}

	profileResp, err := c.userClient.GetProfileByID(ctx, &pb.GetProfileByIDRequest{UserId: userID})
	if err != nil {
		return err
	}
	profile := profileResp.GetProfile()
	if profile == nil || profile.GetUsername() == "" {
		return status.Error(codes.InvalidArgument, "username is required")
	}
	if profile.GetPosition() == "" {
		return status.Error(codes.InvalidArgument, "position is required")
	}

	_, err = c.userClient.CreateProfile(ctx, &pb.UpdateProfileRequest{
		UserId:    userID,
		Username:  profile.GetUsername(),
		AboutInfo: profile.GetAboutInfo(),
		Position:  profile.GetPosition(),
		GitUrl:    gitURL,
	})
	return err
}
