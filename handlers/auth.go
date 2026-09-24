package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go-auth-system/config"
	"go-auth-system/models"
	"go-auth-system/utils"
	"golang.org/x/crypto/bcrypt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func Signup(c *gin.Context) {
	var input struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
		})
		return
	}

	input.Name = strings.TrimSpace(input.Name)
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))

	if input.Name == "" || input.Email == "" || input.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Name, email and password are required",
		})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(input.Password),
		bcrypt.DefaultCost,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to secure password",
		})
		return
	}

	user := models.User{
		ID:       bson.NewObjectID(),
		Name:     input.Name,
		Email:    input.Email,
		Password: string(hashedPassword),
	}

	collection := config.DB.
		Database("go_auth_system").
		Collection("users")

	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	_, err = collection.InsertOne(ctx, user)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create user",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully",
		"user": gin.H{
			"id":    user.ID,
			"name":  user.Name,
			"email": user.Email,
		},
	})
}

func Login(c *gin.Context) {
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
		})
		return
	}

	input.Email = strings.ToLower(strings.TrimSpace(input.Email))

	if input.Email == "" || input.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Email and password are required",
		})
		return
	}

	collection := config.DB.
		Database("go_auth_system").
		Collection("users")

	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	var user models.User

	err := collection.FindOne(
		ctx,
		bson.M{"email": input.Email},
	).Decode(&user)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	err = bcrypt.CompareHashAndPassword(
		[]byte(user.Password),
		[]byte(input.Password),
	)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	token, err := utils.GenerateToken(
		user.ID.Hex(),
		user.Email,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"token":   token,
		"user": gin.H{
			"id":    user.ID,
			"name":  user.Name,
			"email": user.Email,
		},
	})
}

// DeleteUser deletes a user by MongoDB ObjectID.
// This endpoint should be protected by AuthMiddleware.
func DeleteUser(c *gin.Context) {
	userID := c.Param("id")

	objectID, err := bson.ObjectIDFromHex(userID)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID",
		})
		return
	}

	collection := config.DB.
		Database("go_auth_system").
		Collection("users")

	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	result, err := collection.DeleteOne(
		ctx,
		bson.M{"_id": objectID},
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete user",
		})
		return
	}

	if result.DeletedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User deleted successfully",
	})
}

// ForgotPassword creates a password reset token.
// For development/Postman testing, the token is returned in the response.
// In production, this token should be sent through email.
func ForgotPassword(c *gin.Context) {
	var input struct {
		Email string `json:"email"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
		})
		return
	}

	input.Email = strings.ToLower(strings.TrimSpace(input.Email))

	if input.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Email is required",
		})
		return
	}

	usersCollection := config.DB.
		Database("go_auth_system").
		Collection("users")

	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	var user models.User

	err := usersCollection.FindOne(
		ctx,
		bson.M{"email": input.Email},
	).Decode(&user)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to find user",
		})
		return
	}

	// Generate a secure random token.
	randomBytes := make([]byte, 32)

	_, err = rand.Read(randomBytes)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate reset token",
		})
		return
	}

	resetToken := hex.EncodeToString(randomBytes)

	// Store only the SHA-256 hash in MongoDB.
	tokenHash := sha256.Sum256([]byte(resetToken))
	tokenHashString := hex.EncodeToString(tokenHash[:])

	resetCollection := config.DB.
		Database("go_auth_system").
		Collection("password_reset_tokens")

	// Remove old reset tokens for this user.
	_, _ = resetCollection.DeleteMany(
		ctx,
		bson.M{
			"user_id": user.ID,
		},
	)

	resetRecord := models.PasswordResetToken{
		ID:        bson.NewObjectID(),
		UserID:    user.ID,
		TokenHash: tokenHashString,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Used:      false,
		CreatedAt: time.Now(),
	}

	_, err = resetCollection.InsertOne(ctx, resetRecord)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create password reset request",
		})
		return
	}

	// Development response.
	// Normally this token would be sent to the user's email.
	c.JSON(http.StatusOK, gin.H{
		"message":     "Password reset token generated",
		"reset_token": resetToken,
		"expires_in":  "1 hour",
	})
}

// ResetPassword changes the user's password using a valid reset token.
func ResetPassword(c *gin.Context) {
	var input struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
		})
		return
	}

	input.Token = strings.TrimSpace(input.Token)

	if input.Token == "" || input.NewPassword == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Token and new_password are required",
		})
		return
	}

	if len(input.NewPassword) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "New password must be at least 8 characters",
		})
		return
	}

	// Hash the provided reset token.
	tokenHash := sha256.Sum256([]byte(input.Token))
	tokenHashString := hex.EncodeToString(tokenHash[:])

	resetCollection := config.DB.
		Database("go_auth_system").
		Collection("password_reset_tokens")

	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	var resetRecord models.PasswordResetToken

	err := resetCollection.FindOne(
		ctx,
		bson.M{
			"token_hash": tokenHashString,
			"used":       false,
		},
	).Decode(&resetRecord)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired reset token",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to validate reset token",
		})
		return
	}

	if time.Now().After(resetRecord.ExpiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Reset token has expired",
		})
		return
	}

	// Hash the new password.
	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(input.NewPassword),
		bcrypt.DefaultCost,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to secure new password",
		})
		return
	}

	usersCollection := config.DB.
		Database("go_auth_system").
		Collection("users")

	result, err := usersCollection.UpdateOne(
		ctx,
		bson.M{"_id": resetRecord.UserID},
		bson.M{
			"$set": bson.M{
				"password": string(hashedPassword),
			},
		},
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to reset password",
		})
		return
	}

	if result.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found",
		})
		return
	}

	// Mark reset token as used.
	_, err = resetCollection.UpdateOne(
		ctx,
		bson.M{"_id": resetRecord.ID},
		bson.M{
			"$set": bson.M{
				"used": true,
			},
		},
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Password changed but token status update failed",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password reset successful",
	})
}
