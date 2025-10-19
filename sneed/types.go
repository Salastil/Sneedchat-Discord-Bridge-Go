package sneed

type SneedMessage struct {
	MessageID       int                    `json:"message_id"`
	Message         string                 `json:"message"`
	MessageRaw      string                 `json:"message_raw"`
	MessageEditDate int                    `json:"message_edit_date"`
	Author          map[string]interface{} `json:"author"`
	Deleted         bool                   `json:"deleted"`
	IsDeleted       bool                   `json:"is_deleted"`
}

type SneedPayload struct {
	Messages []SneedMessage `json:"messages"`
	Message  *SneedMessage  `json:"message"`
	Delete   interface{}    `json:"delete"`
}
