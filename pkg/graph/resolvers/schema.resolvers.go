package resolvers

import (
	"context"

	auth "github.com/rodrwan/go-auth-svc"
	"github.com/rodrwan/go-auth-svc/pkg/graph"
)

func (r *mutationResolver) Create(ctx context.Context, referenceID string, payload string) (*auth.Auth, error) {
	return r.AuthService.CreateAuthData(ctx, referenceID, []byte(payload))
}

func (r *mutationResolver) Refresh(ctx context.Context, accessToken string, refreshToken string) (*auth.Auth, error) {
	return r.AuthService.RefreshAuthData(ctx, &auth.Auth{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

func (r *mutationResolver) Delete(ctx context.Context, payload string) (*auth.Auth, error) {
	if err := r.AuthService.BlockAuthData(ctx, &auth.Auth{}); err != nil {
		return nil, err
	}

	return nil, nil
}

func (r *queryResolver) Get(ctx context.Context, token string) (string, error) {
	data, err := r.AuthService.GetAuthData(ctx, token)
	if err != nil {
		return "", err
	}

	return data.Data, nil
}

// Mutation returns generated.MutationResolver implementation.
func (r *Resolver) Mutation() graph.MutationResolver { return &mutationResolver{r} }

// Query returns generated.QueryResolver implementation.
func (r *Resolver) Query() graph.QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
