package models

type Comments struct {
	Fname    string `json : "fname" `
	Uuid     string `json : "uuid" `
	Email    string `json : "email"`
	Question string `json : "question"`
	Posttime string `json : "posttime"`
	Count    int64  `json : "count"`
}
