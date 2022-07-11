package main

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"log"
	"net/http"
	"time"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

type ConnectUser struct {
	Websocket *websocket.Conn
	ClientIP  string
}

type Person struct {
	Username string
}

type TokenStruct struct {
	Token string
}

// For income/return in websocket as message
type MessageStruct struct {
	MessageType string	`json:"message_type"`
	MessageText string	`json:"message_text"`
}


// Income to websocket as message
type IncomingMessage struct {
	Token string			`json:"token"`
	ChannelName string		`json:"channel_name"`
	Message MessageStruct	`json:"message"`
	IsLogin bool			`json:"is_login"`
}


// For return in websocket as message
type OutcomeMessage struct {
	Username string			`json:"username"`
	ChannelName string		`json:"channel_name"`
	ItsMe bool				`json:"its_me"`
	Message MessageStruct	`json:"message"`
	SentAt int64			`json:"sent_at"`
}

type Subscribe struct {
	Token string		`json:"token"`
	ChannelName string	`json:"channel_name"`
}

type FirstLogin struct {
	ListChannels []string `json:"list_channels"`
}


func newConnectUser(ws *websocket.Conn, clientIP string) *ConnectUser {
	return &ConnectUser{
		Websocket: ws,
		ClientIP:  clientIP,
	}
}

var users = make(map[ConnectUser]int)
var usersTokens = make(map[ConnectUser]string)
var tokenChannels = make(map[string][]string)
// var channelsTokens = make(map[string][]string)

// THIS IS PIZDOS SYNTAX
var username_tokens = make(map[string]string)

func contains(s []string, e string) bool {
    for _, a := range s {
        if a == e {
            return true
        }
    }
    return false
}

func setHeaders(w http.ResponseWriter) http.ResponseWriter {
	allowedHeaders := "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization, X-CSRF-Token"

	w.Header().Set("content-type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)
	w.Header().Set("Access-Control-Expose-Headers", "Authorization")
	return w
}


func UsernameHandler(w http.ResponseWriter, request *http.Request) {
	setHeaders(w)

	if request.Method == http.MethodOptions {
		resp := make(map[string]string)
		resp["check"] = "true"

		jsonResp, err := json.Marshal(resp)
		if err != nil {
			log.Fatalf("Error happened in JSON marshal. Err: %s", err)
		}
		w.Write(jsonResp)
	} else {
		decoder := json.NewDecoder(request.Body)

		var person Person
		err := decoder.Decode(&person)

		if err != nil {
			panic(err)
		}

		token := uuid.New()
		t := token.String()

		username_tokens[t] = person.Username

		resp := make(map[string]string)
		resp["token"] = t

		jsonResp, err := json.Marshal(resp)
		if err != nil {
			log.Fatalf("Error happened in JSON marshal. Err: %s", err)
		}

		w.Header().Set("content-type", "application/json")
		w.Write(jsonResp)
	}
	return
}


func CheckTokenExists(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)

	var t TokenStruct
	w.Header().Set("Content-Type", "application/json")

	err := json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp := make(map[string]string)
	username := username_tokens[t.Token]

	if username == "" {
		w.WriteHeader(http.StatusNotFound)
		resp["message"] = "Resource Not Found"
	} else {
		resp["username"] = username_tokens[t.Token]

	}

	jsonResp, err := json.Marshal(resp)

	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}

	w.Write(jsonResp)
	return
}


func SubChannelHandler(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)

	if r.Method == http.MethodOptions {
		resp := make(map[string]string)
		resp["check"] = "true"

		jsonResp, err := json.Marshal(resp)
		if err != nil {
			log.Fatalf("Error happened in JSON marshal. Err: %s", err)
		}
		w.Write(jsonResp)
		return
	}

	resp := make(map[string][]string)
	
	if r.Method == http.MethodGet {
		token := r.FormValue("token")

		if _, ok := tokenChannels[token]; !ok {
			http.Error(w, "Not found token or empty list_channels", http.StatusNotFound)
			return
		}

		resp["list_channels"] = tokenChannels[token]
		jsonResp, err := json.Marshal(resp)
		
		if err != nil {
			log.Fatalf("Error happened in JSON marshal. Err: %s", err)
		}
		w.Write(jsonResp)

	} else {
		decoder := json.NewDecoder(r.Body)
		var subscribe Subscribe
		err := decoder.Decode(&subscribe)

		if err != nil {
			panic(err)
		}

		isChannelSubscribed := contains(tokenChannels[subscribe.Token], subscribe.ChannelName)
		if !isChannelSubscribed {
			tokenChannels[subscribe.Token] = append(tokenChannels[subscribe.Token], subscribe.ChannelName)
		}
		
		resp["list_channels"] = tokenChannels[subscribe.Token]
		jsonResp, err := json.Marshal(resp)

		if err != nil {
			log.Fatalf("Error happened in JSON marshal. Err: %s", err)
		}
		w.Write(jsonResp)
	}
}

func ListChannesHandler(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)

	// channel: [token_1, token_2, ...]
	var channelsTokens = make(map[string][]string)
	for token := range tokenChannels {
		channelsList := tokenChannels[token]
		for channel := range channelsList {
			channelsTokens[channelsList[channel]] = append(channelsTokens[channelsList[channel]], token)
		}
	}

	channelNames := make([]string, len(channelsTokens))

	i := 0
	for k := range channelsTokens {
	    channelNames[i] = k
	    i++
	}

	resp := make(map[string][]string)
	resp["list_channels"] = channelNames

	jsonResp, err := json.Marshal(resp)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}
	w.Write(jsonResp)
	return
}

func WebsocketHandler(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)

	upgrader.CheckOrigin = func(r *http.Request) bool { return true }

	ws, _ := upgrader.Upgrade(w, r, nil)

	defer func() {
		if err := ws.Close(); err != nil {
			log.Println("Websocket could not be closed", err.Error())
		}
	}()

	log.Println("Client connected:", ws.RemoteAddr().String())
	var socketClient *ConnectUser = newConnectUser(ws, ws.RemoteAddr().String())
	users[*socketClient] = 0
	log.Println("Number client connected ...", len(users))

	for {
		// TODO IN FUTURE: ReadJSON
		messageType, message, err := ws.ReadMessage()
		if err != nil {
			log.Println("Ws disconnect waiting", err.Error())
			delete(users, *socketClient)
			log.Println("Number of client still connected ...", len(users))
			return
		}

		// Здесь обработка входяшего message
		str := string(message)
		log.Println("1", str)
		var inMessage IncomingMessage
		json.Unmarshal([]byte(str), &inMessage)
		channels := tokenChannels[inMessage.Token]

		if inMessage.IsLogin == true {
			// This is first message after connect to WS
			// Need to {"token": "3efd7baf-8b15-4bee-b7d8-e3e0080d557e", "is_login": true}
			usersTokens[*socketClient] = inMessage.Token

			// First sub if non exists
			subAlready := contains(channels, "general")
			if subAlready != true {
				tokenChannels[inMessage.Token] = append(tokenChannels[inMessage.Token], "general")
			}

			// get list of channels
			outMessage := FirstLogin{tokenChannels[inMessage.Token]}
			jsonResp, _ := json.Marshal(outMessage)
			socketClient.Websocket.WriteMessage(messageType, jsonResp)
		} else {
			for client := range users {
				log.Println(inMessage.Token, channels, inMessage.ChannelName)

				// Send only for subscribers of the channel
				channelExists := contains(channels, inMessage.ChannelName)
				if channelExists {

					// change message object to new
					var outMessage OutcomeMessage
					outMessage.Username = username_tokens[inMessage.Token]
					outMessage.ChannelName = inMessage.ChannelName
					outMessage.Message = inMessage.Message

					socketToken := usersTokens[*socketClient]
					outMessage.ItsMe = false

					if socketToken == inMessage.Token {
						outMessage.ItsMe = true
					}
					timeNow := time.Now()
					outMessage.SentAt = timeNow.Unix()

					jsonResp, _ := json.Marshal(outMessage)

					err = client.Websocket.WriteMessage(messageType, jsonResp)
					if err != nil {
						log.Println("Cloud not send Message to", client.ClientIP, err.Error())
					}
				} else {
					log.Println("Channel name not exists", inMessage.ChannelName)
				}
			}
		}
	}
}


func init() {
	http.HandleFunc("/auth", UsernameHandler)
	http.HandleFunc("/auth/check", CheckTokenExists)
	http.HandleFunc("/sub", SubChannelHandler)
	http.HandleFunc("/channels", ListChannesHandler)
	http.HandleFunc("/ws", WebsocketHandler)
}


func main() {
	serverHost := "localhost:8080"
	log.Println("HTTP Server started\n", serverHost)
	log.Fatal(http.ListenAndServe(serverHost, nil))
}
