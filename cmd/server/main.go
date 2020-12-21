package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	authSvc "github.com/rodrwan/go-auth-svc/pkg/auth"
	"github.com/rodrwan/go-auth-svc/pkg/graph"
	"github.com/rodrwan/go-auth-svc/pkg/graph/resolvers"
)

const defaultPort = "8080"

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	accessSecret := os.Getenv("ACCESS_SECRET")
	refreshSecret := os.Getenv("REFRESH_SECRET")

	gqlsrv := handler.NewDefaultServer(
		graph.NewExecutableSchema(
			graph.Config{
				Resolvers: &resolvers.Resolver{
					AuthService: &authSvc.Service{
						AccessSecret:  []byte(accessSecret),
						RefreshSecret: []byte(refreshSecret),
					},
				},
			},
		),
	)

	router := http.NewServeMux()

	router.Handle("/", playground.Handler("GraphQL playground", "/query"))
	router.Handle("/query", gqlsrv)

	log.Printf("connect to http://localhost:%s/ for GraphQL playground", port)

	appAddr := fmt.Sprintf(":%s", port)
	srv := &http.Server{
		Addr:    appAddr,
		Handler: router,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	//Wait for interrupt signal to gracefully shutdown the server with a timeout of 10 seconds
	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit
	log.Println("Shutdown Server ...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server Shutdown:", err)
	}

	log.Println("Server exiting")
}
