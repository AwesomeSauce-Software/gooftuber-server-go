package helpers

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"os"
	"time"
)

type Activity struct {
	VoiceActivity float64 `json:"voice_activity"`
	Action        string  `json:"action"`
}

type Avatar struct {
	Filename string `json:"filename"`
	Base64   string `json:"base64"`
}

type Avatars struct {
	Avatar []Avatar `json:"avatars"`
}

type Config struct {
	Port          string          `json:"port"`
	DiscordToken  string          `json:"discordToken"`
	Sessions      []Session       `json:"sessions"`
	SessionAskIDs []SessionAskIDs `json:"sessionAskIDs"`
}

type Session struct {
	SessionID       string   `json:"sessionID"`
	UserID          string   `json:"userID"`
	AllowedSessions []string `json:"allowedSessions"`
}

type SessionAskIDs struct {
	InviteID       string `json:"inviteid"`
	SessionID      string `json:"session_id"`
	AllowSessionID string `json:"allow_session_id"`
}

type VerifyCodes struct {
	VerifyCode string
	UserID     string
	Expires    int64
}

type CurrentData struct {
	SessionID string   `json:"session_id"`
	Activity  Activity `json:"activity"`
	Timestamp int64    `json:"timestamp"`
}

type CurrentDataResponse struct {
	UserID   string   `json:"userid"`
	Activity Activity `json:"activity"`
}

type Response struct {
	Message string `json:"message"`
}

type ResponseToken struct {
	Message   string `json:"message"`
	SessionID string `json:"session_id"`
}

func SaveConfig(config Config) {
	file, err := os.Create("config.json")
	HandleError(err, false)
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			HandleError(err, false)
		}
	}(file)

	b, err := json.MarshalIndent(config, "", "    ")
	HandleError(err, false)

	_, err = file.Write(b)
	HandleError(err, false)
}

func SaveEmptyConfig() {
	var config Config

	config.Sessions = make([]Session, 0)
	config.SessionAskIDs = make([]SessionAskIDs, 0)

	file, err := os.Create("config.json")
	HandleError(err, false)
	defer file.Close()

	b, err := json.MarshalIndent(config, "", "    ")
	HandleError(err, false)

	_, err = file.Write(b)
	HandleError(err, false)

}

func LoadConfig() Config {
	file, err := os.Open("config.json")
	HandleError(err, false)
	defer file.Close()

	decoder := json.NewDecoder(file)
	config := Config{}
	err = decoder.Decode(&config)
	HandleError(err, false)

	return config
}

func RemoveSession(sessionID string, sessions []Session) []Session {
	var newSessions []Session
	for _, s := range sessions {
		if s.SessionID != sessionID {
			newSessions = append(newSessions, s)
		}
	}
	return newSessions
}

func SessionExists(userID string, sessions []Session) []Session {
	for _, s := range sessions {
		if s.UserID == userID {
			//	remove session
			return RemoveSession(s.SessionID, sessions)
		}
	}
	return sessions
}

func AddAllowedSession(sessionID string, sessionToAdd string, sessionAdd *[]Session) {
	for _, s := range *sessionAdd {
		if s.SessionID == sessionID {
			s.AllowedSessions = append(s.AllowedSessions, sessionToAdd)
		}
	}
}

func DenyInvite(sessionAskID string, sessionAskIDs []SessionAskIDs) []SessionAskIDs {
	var newSessionAskIDs []SessionAskIDs
	for _, s := range sessionAskIDs {
		if s.InviteID != sessionAskID {
			newSessionAskIDs = append(newSessionAskIDs, s)
		}
	}
	return newSessionAskIDs
}

func CodeExists(code string, codes []VerifyCodes) bool {
	for _, c := range codes {
		if c.VerifyCode == code {
			return true
		}
	}
	return false
}

func CodeGet(code string, codes []VerifyCodes) VerifyCodes {
	for _, c := range codes {
		if c.VerifyCode == code {
			return c
		}
	}
	return VerifyCodes{}
}

func DoesFileExist(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func DoesFolderExist(foldername string) bool {
	info, err := os.Stat(foldername)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

func HandleError(err error, fatal bool) {
	if err != nil {
		if fatal {
			panic(err)
		} else {
			println(err.Error())
		}
	}
}

func RemoveVerifyCode(code string, codes []VerifyCodes) []VerifyCodes {
	var newCodes []VerifyCodes
	for _, c := range codes {
		if c.VerifyCode != code {
			newCodes = append(newCodes, c)
		}
	}
	return newCodes
}

func RemoveExpired(codes []VerifyCodes) []VerifyCodes {
	var newCodes []VerifyCodes
	for _, c := range codes {
		if c.Expires > time.Now().Unix() {
			newCodes = append(newCodes, c)
		}
	}
	return newCodes
}

func DoesUserExist(userID string, sessions []Session) bool {
	for _, s := range sessions {
		if s.UserID == userID {
			return true
		}
	}
	return false
}

func DoesInviteExist(inviteID string, sessionAskIDs []SessionAskIDs) bool {
	for _, s := range sessionAskIDs {
		if s.InviteID == inviteID {
			return true
		}
	}
	return false
}

func GetInvite(inviteID string, sessionAskIDs []SessionAskIDs) SessionAskIDs {
	for _, s := range sessionAskIDs {
		if s.InviteID == inviteID {
			return s
		}
	}
	return SessionAskIDs{}
}

func EncodeFileBase64(filename string) string {
	// Open file on disk.
	f, _ := os.Open(filename)
	reader := bufio.NewReader(f)
	content, _ := io.ReadAll(reader)

	// Encode as base64.
	encoded := base64.StdEncoding.EncodeToString(content)
	return encoded
}

func GetAvatars(userID string) (error, Avatars) {
	if !DoesFolderExist("avatars/" + userID) {
		return errors.New("folder does not exist"), Avatars{}
	}

	files, err := os.ReadDir("avatars/" + userID)
	if err != nil {
		return err, Avatars{}
	}

	var avatars Avatars
	for _, f := range files {
		avatars.Avatar = append(avatars.Avatar, Avatar{
			Filename: f.Name(),
			Base64:   EncodeFileBase64("avatars/" + userID + "/" + f.Name()),
		})
	}
	return nil, avatars
}

func SaveAvatars(avatars Avatars, userID string) error {
	if !DoesFolderExist("avatars/" + userID) {
		err := os.Mkdir("avatars/"+userID, 0777)
		if err != nil {
			return err
		}
	}

	for _, a := range avatars.Avatar {
		decoded, err := base64.StdEncoding.DecodeString(a.Base64)
		if err != nil {
			return err
		}

		err = os.WriteFile("avatars/"+userID+"/"+a.Filename, decoded, 0777)
		if err != nil {
			return err
		}
	}
	return nil
}

func SetAvatar(avatars Avatars, userid string) error {
	if !DoesFolderExist("avatars/" + userid) {
		err := os.Mkdir("avatars/"+userid, 0777)
		if err != nil {
			return err
		}
	}

	for _, a := range avatars.Avatar {
		decoded, err := base64.StdEncoding.DecodeString(a.Base64)
		if err != nil {
			return err
		}

		err = os.WriteFile("avatars/"+userid+"/"+a.Filename, decoded, 0777)
		if err != nil {
			return err
		}
	}
	return nil
}

func IsSessionValid(sessionID string, sessions []Session) bool {
	for _, s := range sessions {
		if s.SessionID == sessionID {
			return true
		}
	}
	return false
}

func FileHeaderBase64(header multipart.File) string {
	reader := bufio.NewReader(header)
	content, _ := io.ReadAll(reader)

	// Encode as base64.
	encoded := base64.StdEncoding.EncodeToString(content)
	return encoded
}

func ReplaceOrAddCurrentData(data []CurrentData, newData CurrentData) []CurrentData {
	for i, d := range data {
		if d.SessionID == newData.SessionID {
			data[i] = newData
			return data
		}
	}
	return append(data, newData)
}

func RefreshCurrentData(data []CurrentData) []CurrentData {
	var newData []CurrentData
	for _, d := range data {
		if d.Timestamp+60 < time.Now().Unix() {
			newData = append(newData, d)
		}
	}
	return newData
}

func HasAccessToSession(sessionID string, sessions []Session, clientID string) bool {
	for _, s := range sessions {
		if s.SessionID == sessionID {
			if s.UserID == clientID {
				return true
			}
			for _, a := range s.AllowedSessions {
				if a == clientID {
					return true
				}
			}
		}
	}
	return false
}

func HasCurrentData(sessionID string, data []CurrentData) bool {
	for _, d := range data {
		if d.SessionID == sessionID {
			return true
		}
	}
	return false
}

func GetCurrentData(sessionID string, data []CurrentData) CurrentData {
	for _, d := range data {
		if d.SessionID == sessionID {
			return d
		}
	}
	return CurrentData{}
}
