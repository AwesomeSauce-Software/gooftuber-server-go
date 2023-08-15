package main

import (
	"minituber-server/helpers"
	"testing"
)

func TestGetSessionid(t *testing.T) {
	config := helpers.Config{
		Sessions: []helpers.Session{
			{SessionID: "123", UserID: "user1"},
			{SessionID: "456", UserID: "user2"},
		},
	}

	sessionid := helpers.GetSessionID("user1", config)
	if sessionid != "123" {
		t.Errorf("GetSessionid(\"user1\") = %v; want 123", sessionid)
	}

	sessionid = helpers.GetSessionID("user3", config)
	if sessionid != "" {
		t.Errorf("GetSessionid(\"user3\") = %v; want \"\"", sessionid)
	}
}

func TestGetUserid(t *testing.T) {
	config := helpers.Config{
		Sessions: []helpers.Session{
			{SessionID: "123", UserID: "user1"},
			{SessionID: "456", UserID: "user2"},
		},
	}

	userid := helpers.GetUserid("123", config)
	if userid != "user1" {
		t.Errorf("GetUserid(\"123\") = %v; want user1", userid)
	}

	userid = helpers.GetUserid("789", config)
	if userid != "" {
		t.Errorf("GetUserid(\"789\") = %v; want \"\"", userid)
	}
}

func TestReplaceOrAddCurrentData(t *testing.T) {
	currentData := []helpers.CurrentData{
		{SessionID: "1234", Activity: helpers.Activity{
			VoiceActivity: 1.0,
			Action:        "action1",
		}},
		{SessionID: "5678", Activity: helpers.Activity{
			VoiceActivity: 0.5,
			Action:        "action2",
		}},
	}

	newData := helpers.CurrentData{SessionID: "1234", Activity: helpers.Activity{
		VoiceActivity: 0.5,
		Action:        "action1",
	}}
	newCurrentData := helpers.ReplaceOrAddCurrentData(currentData, newData)
	if len(newCurrentData) != 2 {
		t.Errorf("len(newCurrentData) = %v; want 2", len(newCurrentData))
	}
	if newCurrentData[0].Activity.VoiceActivity != 0.5 {
		t.Errorf("newCurrentData[0].Activity.VoiceActivity = %v; want 0.5", newCurrentData[0].Activity.VoiceActivity)
	}

	newData = helpers.CurrentData{SessionID: "9012", Activity: helpers.Activity{
		VoiceActivity: 0.5,
		Action:        "action2",
	}}
	newCurrentData = helpers.ReplaceOrAddCurrentData(currentData, newData)
	if len(newCurrentData) != 3 {
		t.Errorf("len(newCurrentData) = %v; want 3", len(newCurrentData))
	}
	if newCurrentData[2].Activity.VoiceActivity != 0.5 {
		t.Errorf("newCurrentData[2].Activity.VoiceActivity = %v; want 0.5", newCurrentData[2].Activity.VoiceActivity)
	}
}

func TestGetCurrentData(t *testing.T) {
	currentData := []helpers.CurrentData{
		{SessionID: "1234", Activity: helpers.Activity{
			VoiceActivity: 1.0,
			Action:        "action1",
		}},
		{SessionID: "5678", Activity: helpers.Activity{
			VoiceActivity: 0.5,
			Action:        "",
		}},
	}

	cd := helpers.GetCurrentData("1234", currentData)
	if cd.Activity.Action != "action1" {
		t.Errorf("cd.Activity.Action = %v; want action1", cd.Activity.Action)
	}

	cd = helpers.GetCurrentData("5678", currentData)
	if cd.Activity.Action != "" {
		t.Errorf("cd.Activity.Action = %v; want \"\"", cd.Activity.Action)
	}
}

func TestHasCurrentData(t *testing.T) {
	currentData := []helpers.CurrentData{
		{SessionID: "1234", Activity: helpers.Activity{
			VoiceActivity: 1.0,
			Action:        "action1",
		}},
		{SessionID: "5678", Activity: helpers.Activity{
			VoiceActivity: 0.5,
			Action:        "action2",
		}},
	}

	hasData := helpers.HasCurrentData("1234", currentData)
	if !hasData {
		t.Errorf("HasCurrentData(\"user1\") = false; want true")
	}

	hasData = helpers.HasCurrentData("9012", currentData)
	if hasData {
		t.Errorf("HasCurrentData(\"user3\") = true; want false")
	}
}

func TestHasAccessToSession(t *testing.T) {
	sessions := []helpers.Session{
		{SessionID: "123", UserID: "user1", AllowedSessions: []string{"456"}},
		{SessionID: "456", UserID: "user2"},
	}

	hasAccess := helpers.HasAccessToSession("123", sessions, "456")
	if !hasAccess {
		t.Errorf("HasAccessToSession(\"123\", \"456\") = false; want true")
	}

	hasAccess = helpers.HasAccessToSession("123", sessions, "789")
	if hasAccess {
		t.Errorf("HasAccessToSession(\"123\", \"789\") = true; want false")
	}

	hasAccess = helpers.HasAccessToSession("123", sessions, "123")
	if hasAccess {
		t.Errorf("HasAccessToSession(\"123\", \"123\") = true; want false")
	}
}
