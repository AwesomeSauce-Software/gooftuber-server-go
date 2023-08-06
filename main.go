package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"log"
	"math/rand"
	"minituber-server/helpers"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-co-op/gocron"
)

var upgrader = websocket.Upgrader{} // use default options

// TODO: Add character frame update to websocket

func initialiseRoutes() {
	r := mux.NewRouter()
	r.HandleFunc("/ping", ping).Methods("GET")
	r.HandleFunc("/validsession/{sessionid}", validSession).Methods("GET")
	r.HandleFunc("/verify/{userid}", verify).Methods("GET")
	r.HandleFunc("/verify/{userid}/{code}", verifyCode).Methods("GET")
	r.HandleFunc("/request-session/{sourcesession}/{userid}", requestSession).Methods("GET")
	r.HandleFunc("/allow-session/{inviteid}", allowSession).Methods("GET")
	r.HandleFunc("/deny-session/{inviteid}", denySession).Methods("GET")
	r.HandleFunc("/upload-avatar/{sessionid}", uploadAvatars).Methods("POST")
	r.HandleFunc("/upload-own/{code}", uploadOwn).Methods("POST")
	r.HandleFunc("/get-avatars/{sessionid}/{userid}", getAvatars).Methods("GET")
	r.HandleFunc("/websocket/{sessionid}/{userids}", websocketHandler)
	r.HandleFunc("/receive-upload/{code}", listenAvatar)
	r.HandleFunc("/request-upload/{sessionid}", requestUpload)

	// CORS
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Access-Control-Allow-Origin", "*")
			w.Header().Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Add("Access-Control-Allow-Headers", "Content-Type")
			next.ServeHTTP(w, r)
		})
	})

	server := http.Server{
		Addr:    ":" + config.Port,
		Handler: r,
		TLSConfig: &tls.Config{
			NextProtos: []string{"h2", "http/1.1"},
		},
	}

	fmt.Printf("Server listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		fmt.Println(err)
	}

}

var config helpers.Config
var verifyCodes []helpers.VerifyCodes
var currentData []helpers.CurrentData
var session *discordgo.Session

func GetSessionID(userid string) string {
	for _, s := range config.Sessions {
		if s.UserID == userid {
			return s.SessionID
		}
	}
	return ""
}

func GetUserid(sessionid string) string {
	for _, s := range config.Sessions {
		if s.SessionID == sessionid {
			return s.UserID
		}
	}
	return ""
}

func websocketHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	sessionid := vars["sessionid"]
	userids := vars["userids"]

	if !helpers.IsSessionValid(sessionid, config.Sessions) {
		w.WriteHeader(401)
		return
	}

	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	defer func(c *websocket.Conn) {
		err := c.Close()
		if err != nil {
			helpers.HandleError(err, false)
		}
	}(c)

	useridsSplit := strings.Split(userids, ",")
	if userids == "0" {
		useridsSplit = []string{}
	}

	for {
		mt, message, err := c.ReadMessage()
		helpers.HandleError(err, false)
		//log.Printf("recv: %s", message)
		if strings.HasPrefix(string(message), "SEND") {
			modded := []byte(strings.Replace(string(message), "SEND", "", 1))
			var formatted helpers.Activity
			err := json.Unmarshal(modded, &formatted)
			helpers.HandleError(err, false)
			currentData = helpers.ReplaceOrAddCurrentData(currentData, helpers.CurrentData{
				SessionID: sessionid,
				Activity:  formatted,
				Timestamp: time.Now().Unix(),
			})
			err = c.WriteMessage(mt, []byte("OK"))
			helpers.HandleError(err, false)
		}
		var response helpers.DataWrapper
		for _, userid := range useridsSplit {
			if !helpers.HasAccessToSession(sessionid, config.Sessions, GetSessionID(userid)) {
				err := c.WriteMessage(mt, []byte("ERROR Session not allowed!"))
				helpers.HandleError(err, false)
				continue
			}
			if !helpers.HasCurrentData(GetSessionID(userid), currentData) {
				continue
			}
			response.Data = append(response.Data, helpers.CurrentDataResponse{
				UserID:   userid,
				Activity: helpers.GetCurrentData(GetSessionID(userid), currentData).Activity,
			})
		}
		if response.Data != nil {
			encoded, _ := json.Marshal(response)
			err = c.WriteMessage(mt, encoded)
			helpers.HandleError(err, false)
		}
	}
}

func listenAvatar(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	code := vars["code"]

	if !helpers.IsCodeValid(code, config.UploadCodes) {
		w.WriteHeader(401)
		return
	}

	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}

	for {
		//check if code is still valid
		if !helpers.IsCodeValid(code, config.UploadCodes) {
			// check if file uploaded
			if helpers.GetUploadedAvatar(code, config.UploadedAvatar).Uploaded {
				err := c.WriteMessage(websocket.TextMessage, []byte("OK"))
				helpers.HandleError(err, false)
				err = c.Close()
				helpers.HandleError(err, false)
				return
			}
			err := c.WriteMessage(websocket.TextMessage, []byte("ERROR Code is invalid!"))
			helpers.HandleError(err, false)
			err = c.Close()
			helpers.HandleError(err, false)
			return
		}
	}
}

func ping(w http.ResponseWriter, _ *http.Request) {
	pingPong := helpers.Response{
		Message: "Pong!",
	}
	_ = json.NewEncoder(w).Encode(pingPong)
}

func validSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	key := vars["sessionid"]

	if helpers.IsSessionValid(key, config.Sessions) {
		_ = json.NewEncoder(w).Encode(helpers.Response{Message: "Session is valid!"})
	} else {
		w.WriteHeader(401)
		_ = json.NewEncoder(w).Encode(helpers.Response{Message: "Session is invalid!"})
	}
}

func addToVerifiedSessions(userid string, sessionid string, code string) {
	config.Sessions = helpers.SessionExists(userid, config.Sessions)
	config.Sessions = append(config.Sessions, helpers.Session{
		SessionID: sessionid,
		UserID:    userid,
	})
	verifyCodes = helpers.RemoveVerifyCode(code, verifyCodes)
}

func verify(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	key := vars["userid"]

	verificationCode := ""

	for {
		for i := 0; i < 6; i++ {
			verificationCode += strconv.Itoa(rand.Intn(9-0) + 0)
		}

		if helpers.DoesVerificationCodeExist(verificationCode, verifyCodes) {
			verificationCode = ""
		} else {
			break
		}
	}

	verifyCodes = append(verifyCodes, helpers.VerifyCodes{
		VerifyCode: verificationCode,
		UserID:     key,
		Expires:    time.Now().Unix() + 300,
	})

	sendMessage(key, fmt.Sprintf("Please verify your identity by entering this code in the software: `%s`\n\n"+
		"The code will expire in 5 minutes. If you did not request this verification code, please ignore this "+
		"message.", verificationCode))

	_ = json.NewEncoder(w).Encode(helpers.Response{Message: "Verification code generation initiated!"})
}

func verifyCode(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userid := vars["userid"]
	code := vars["code"]

	sessionId := ""
	for {
		for i := 0; i < 10; i++ {
			sessionId += strconv.Itoa(rand.Intn(9-0) + 0)
		}

		if helpers.IsSessionValid(sessionId, config.Sessions) {
			sessionId = ""
		} else {
			break
		}
	}

	if helpers.CodeExists(code, verifyCodes) {
		codeSaved := helpers.CodeGet(code, verifyCodes)
		if codeSaved.UserID == userid && codeSaved.Expires > time.Time.Unix(time.Now()) {
			sendMessage(userid, "Verification successful! Have fun!")
			_ = json.NewEncoder(w).Encode(helpers.ResponseToken{Message: "Verification successful!", SessionID: sessionId})
			addToVerifiedSessions(userid, sessionId, code)
			return
		} else {
			sendMessage(userid, "Verification code incorrect! Please try again.")
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(helpers.Response{Message: "Verification code incorrect!"})
			return
		}
	} else {
		sendMessage(userid, "Verification code incorrect! Please try again.")
		w.WriteHeader(401)
		_ = json.NewEncoder(w).Encode(helpers.Response{Message: "Verification code incorrect!"})
		return
	}
}

func requestSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sourcesession := vars["sourcesession"]
	userid := vars["userid"]

	if !helpers.IsSessionValid(sourcesession, config.Sessions) {
		sendMessage(userid, "Invalid session ID!")
		_ = json.NewEncoder(w).Encode(helpers.Response{Message: "Invalid session ID!"})
		w.WriteHeader(401)
		return
	}

	if !helpers.DoesUserExist(userid, config.Sessions) {
		sendMessage(userid, "Invalid user ID!")
		_ = json.NewEncoder(w).Encode(helpers.Response{Message: "Invalid user ID!"})
		w.WriteHeader(401)
		return
	}

	sessionInviteID := ""
	for {
		for i := 0; i < 10; i++ {
			sessionInviteID += strconv.Itoa(rand.Intn(9-0) + 0)
		}

		if helpers.DoesInviteExist(sessionInviteID, config.SessionAskIDs) {
			sessionInviteID = ""
		} else {
			break
		}
	}

	config.SessionAskIDs = append(config.SessionAskIDs, helpers.SessionAskIDs{
		InviteID:       sessionInviteID,
		SessionID:      sourcesession,
		AllowSessionID: GetSessionID(userid),
	})

	user, _ := session.User(userid)

	sendMessage(userid, fmt.Sprintf("User <@%s> is requesting access to your session. Open this link to allow "+
		"access: https://auth.awesomesauce.software/?username=%s&inviteid=%s", GetUserid(sourcesession), user.Username, sessionInviteID))

	_ = json.NewEncoder(w).Encode(helpers.Response{Message: "Session request sent!"})
}

func allowSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	inviteID := vars["inviteid"]
	if !helpers.DoesInviteExist(inviteID, config.SessionAskIDs) {
		_ = json.NewEncoder(w).Encode(helpers.Response{Message: "Invalid invite ID!"})
		w.WriteHeader(401)
		return
	}
	sessionId := helpers.GetInvite(inviteID, config.SessionAskIDs).SessionID
	allowSessionId := helpers.GetInvite(inviteID, config.SessionAskIDs).AllowSessionID

	if !helpers.IsSessionValid(sessionId, config.Sessions) || !helpers.IsSessionValid(allowSessionId, config.Sessions) {
		_ = json.NewEncoder(w).Encode(helpers.Response{Message: "Invalid session ID!"})
		w.WriteHeader(401)
		return
	}

	config.Sessions = helpers.AddAllowedSession(sessionId, allowSessionId, config.Sessions)
	_ = json.NewEncoder(w).Encode(helpers.Response{Message: "Session allowed!"})
}

func denySession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	inviteID := vars["inviteid"]

	if !helpers.DoesInviteExist(inviteID, config.SessionAskIDs) {
		_ = json.NewEncoder(w).Encode(helpers.Response{Message: "Invalid invite ID!"})
		w.WriteHeader(401)
		return
	}

	config.SessionAskIDs = helpers.DenyInvite(inviteID, config.SessionAskIDs)
	_ = json.NewEncoder(w).Encode(helpers.Response{Message: "Session denied!"})
}

func getAvatars(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionid := vars["sessionid"]
	userid := vars["userid"]

	if !helpers.IsSessionValid(sessionid, config.Sessions) {
		_ = json.NewEncoder(w).Encode(helpers.Response{Message: "Invalid session ID!"})
		w.WriteHeader(401)
		return
	}

	if userid == "0" {
		userid = GetUserid(sessionid)
	}

	err, avatars := helpers.GetAvatars(userid)
	if err != nil {
		_ = json.NewEncoder(w).Encode(helpers.Response{Message: err.Error()})
		w.WriteHeader(400)
		return
	}

	_ = json.NewEncoder(w).Encode(avatars)
}

func requestUpload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionid := vars["sessionid"]

	if !helpers.IsSessionValid(sessionid, config.Sessions) {
		_ = json.NewEncoder(w).Encode(helpers.Response{Message: "Invalid session ID!"})
		w.WriteHeader(401)
		return
	}

	uploadCode := ""

	for {
		for i := 0; i < 6; i++ {
			uploadCode += strconv.Itoa(rand.Intn(9-0) + 0)
		}

		if !helpers.IsCodeValid(uploadCode, config.UploadCodes) {
			uploadCode = ""
		} else {
			break
		}
	}

	config.UploadCodes = append(config.UploadCodes, helpers.UploadCode{
		UploadCode: uploadCode,
		UserID:     GetUserid(sessionid),
		Expires:    time.Now().Add(time.Minute * 5).Unix(),
	})

	_ = json.NewEncoder(w).Encode(helpers.ResponseCode{Message: "Upload code requested!", Code: uploadCode})
}

func uploadAvatars(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionid := vars["sessionid"]

	if !helpers.IsSessionValid(sessionid, config.Sessions) {
		_ = json.NewEncoder(w).Encode(helpers.Response{Message: "Invalid session ID!"})
		w.WriteHeader(401)
		return
	}

	var av helpers.Avatars

	err := json.NewDecoder(r.Body).Decode(&av)
	if err != nil {
		_ = json.NewEncoder(w).Encode(helpers.Response{Message: err.Error()})
		w.WriteHeader(400)
		return
	}

	err = helpers.SaveAvatars(av, GetUserid(sessionid))
	if err != nil {
		_ = json.NewEncoder(w).Encode(helpers.Response{Message: err.Error()})
		w.WriteHeader(400)
		return
	}
	_ = json.NewEncoder(w).Encode(helpers.Response{Message: "Avatars saved!"})
}

func uploadOwn(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	code := vars["code"]

	if !helpers.IsCodeValid(code, config.UploadCodes) {
		_ = json.NewEncoder(w).Encode(helpers.Response{Message: "Invalid upload code!"})
		w.WriteHeader(401)
		return
	}

	var av helpers.Avatars

	err := json.NewDecoder(r.Body).Decode(&av)
	if err != nil {
		_ = json.NewEncoder(w).Encode(helpers.Response{Message: err.Error()})
		w.WriteHeader(400)
		return
	}
	uploadCode := helpers.GetUploadCode(code, config.UploadCodes)
	if uploadCode.Expires < time.Now().Unix() {
		//remove code
		config.UploadCodes = helpers.RemoveUploadCode(code, config.UploadCodes)
		_ = json.NewEncoder(w).Encode(helpers.Response{Message: "Upload code expired!"})
		w.WriteHeader(401)
		return
	}

	err = helpers.SaveAvatars(av, uploadCode.UserID)
	if err != nil {
		_ = json.NewEncoder(w).Encode(helpers.Response{Message: err.Error()})
		w.WriteHeader(400)
		return
	}
	// set UploadedAvatar.Uploaded to true
	config.UploadCodes = helpers.RemoveUploadCode(code, config.UploadCodes)
	config.UploadedAvatar = append(config.UploadedAvatar, helpers.UploadedAvatar{
		UploadCode: code,
		Uploaded:   true,
	})
	_ = json.NewEncoder(w).Encode(helpers.Response{Message: "Avatars saved!"})
}

func sendMessage(userid string, message string) {
	create, err := session.UserChannelCreate(userid)
	helpers.HandleError(err, false)
	_, err = session.ChannelMessageSend(create.ID, message)
	helpers.HandleError(err, false)
}

func task() {
	verifyCodes = helpers.RemoveExpired(verifyCodes)
	currentData = helpers.RefreshCurrentData(currentData)
	helpers.SaveConfig(config)
}

func prepareScheduler() {
	s := gocron.NewScheduler(time.UTC)
	_, err := s.Every(1).Minutes().Do(task)
	if err != nil {
		return
	}
	if err != nil {
		println(err.Error())
		return
	}
	// Start the scheduler in a thread
	s.StartAsync()
}

func main() {
	if helpers.DoesFileExist("config.json") {
		config = helpers.LoadConfig()
		if config.DiscordToken == "" {
			fmt.Println("No Discord Token specified! Set it and restart!")
			os.Exit(1)
		}
	} else {
		helpers.SaveEmptyConfig()
		fmt.Println("Please edit config.json and restart the server.")
		os.Exit(1)
	}
	discord, err := discordgo.New("Bot " + config.DiscordToken)
	discord.Identify.Intents = discordgo.IntentsDirectMessages
	helpers.HandleError(err, true)
	_, _ = discord.ApplicationCommandBulkOverwrite(config.DiscordAppID, "", []*discordgo.ApplicationCommand{
		{
			Name:        "id",
			Description: "Get your Discord ID",
		},
	})

	discord.AddHandler(func(s *discordgo.Session, i *discordgo.InteractionCreate) {
		if i.ApplicationCommandData().Name == "id" {
			var userid string
			if i.Member != nil {
				userid = i.Member.User.ID
			} else {
				userid = i.User.ID
			}
			var fields = []*discordgo.MessageEmbedField{
				{
					Name:   "Registered",
					Value:  fmt.Sprintf("%t", helpers.DoesUserExist(userid, config.Sessions)),
					Inline: true,
				},
			}

			if helpers.DoesUserExist(userid, config.Sessions) {
				fields = append(fields, &discordgo.MessageEmbedField{
					Name:   "Session ID",
					Value:  fmt.Sprintf("`%s`", GetSessionID(userid)),
					Inline: true,
				})
			}

			embed := &discordgo.MessageEmbed{
				Title:       "Information",
				Description: fmt.Sprintf("Your ID is `%s`", userid),
				Color:       0x1264DF,
				Fields:      fields,
			}

			_ = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
				Type: discordgo.InteractionResponseChannelMessageWithSource,
				Data: &discordgo.InteractionResponseData{
					Flags:  discordgo.MessageFlagsEphemeral,
					Embeds: []*discordgo.MessageEmbed{embed},
				},
			})
		}
	})

	session = discord
	if err != nil {
		// Handle the error
	}
	err = discord.Open()
	err = session.UpdateWatchStatus(0, "your goofy avatars!")
	helpers.HandleError(err, false)
	prepareScheduler()
	initialiseRoutes()
}
