package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"go-auth-system/config"
	"go-auth-system/handlers"
	"go-auth-system/middleware"
)

func main() {

	// Connect to MongoDB
	err := config.ConnectDB()

	if err != nil {
		log.Fatal("MongoDB connection failed:", err)
	}

	// Create Gin router
	r := gin.Default()

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"message": "Go Auth System is running",
		})
	})

	// Start server

	r.POST("/api/auth/signup", handlers.Signup)
	r.POST("/api/auth/login", handlers.Login)

	r.GET(
	"/api/auth/me",
	middleware.AuthMiddleware(),
	func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "You are authenticated",
			"user":    c.MustGet("user"),
		})
	},
)

	r.Run(":8080")
}

