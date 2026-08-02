package sneed

type SneedMessage struct {
	MessageID       int                    `json:"message_id"`
	MessageUUID     string                 `json:"message_uuid"`
	Message         string                 `json:"message"`
	MessageRaw      string                 `json:"message_raw"`
	MessageDate     int                    `json:"message_date"`
	MessageEditDate int                    `json:"message_edit_date"`
	Author          map[string]interface{} `json:"author"`
	Deleted         bool                   `json:"deleted"`
	IsDeleted       bool                   `json:"is_deleted"`
}

type SneedMOTD struct {
	Author          map[string]interface{} `json:"author"`
	Message         string                 `json:"message"`
	MessageRaw      string                 `json:"message_raw"`
	MessageUUID     string                 `json:"message_uuid"`
	MessageEditDate int                    `json:"message_edit_date"`
	MessageDate     int                    `json:"message_date"`
	RoomID          int                    `json:"room_id"`
}

type SneedPayload struct {
	Messages []SneedMessage `json:"messages"`
	Message  *SneedMessage  `json:"message"`
	Delete   []string       `json:"delete"`
	MOTD     *SneedMOTD     `json:"motd"`
}
