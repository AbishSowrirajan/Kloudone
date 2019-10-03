package models

type CreateUsers struct {
	Fname string `json : "fname" `
	Lname string `json : "lname" `
	Psw   []byte `json : "psw" `
	Uuid  string `json : "uuid" `
	Email string `json : "email"`
}

type LoginDetails struct {
	Email string `json :"uname" `
	Psw   []byte `json : "psw"`
}

type Uuid struct {
	Email string `json : "uname"`
	Uuid  string `json : "Uuid"`
}
