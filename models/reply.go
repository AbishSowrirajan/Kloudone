package models

type Reply struct {
	Fname    string `json : "fname" `
	Uuid     string `json : "uuid" `
	RootId   string `json : ""rootId`
	ParentId string `json : "parentId"`
	Comment  string `json : "comment"`
	Posttime string `json : "posttime"`
	Count    int64  `json : "count"`
}
