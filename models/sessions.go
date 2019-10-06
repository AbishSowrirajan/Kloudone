package models

import "time"

type Sessions struct {
	SessionId string    `json : "sessionid"`
	Fname     string    `json : "fname" `
	Uuid      string    `json : "uuid" `
	Email     string    `json : "email"`
	Cookies   string    `json : "cookies"`
	Posttime  time.Time `json : "posttime"`
	LoggedIn  bool      `json : "login"`
}
