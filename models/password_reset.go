package models

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

type PasswordResetToken struct {
	ID        bson.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID    bson.ObjectID `bson:"user_id" json:"user_id"`
	TokenHash string        `bson:"token_hash" json:"-"`
	ExpiresAt time.Time     `bson:"expires_at" json:"expires_at"`
	Used      bool          `bson:"used" json:"used"`
	CreatedAt time.Time     `bson:"created_at" json:"created_at"`
}
