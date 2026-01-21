package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/banditmoscow1337/safem/protocol/client"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type TUI struct {
	App         *tview.Application
	Pages       *tview.Pages
	ChatView    *tview.TextView
	InputField  *tview.InputField
	FriendsList *tview.List
	StatusView  *tview.TextView

	Client      *client.Client
	ChatBuffers map[string]string
	bufferMu    sync.RWMutex
	ActiveID    string

	// Typing State
	typingTimers map[string]*time.Timer
	lastTyped    time.Time
}

func (t *TUI) setupLayout() {
	// Init typing map
	t.typingTimers = make(map[string]*time.Timer)

	t.ChatView = tview.NewTextView().
		SetDynamicColors(true).
		SetWordWrap(true).
		SetScrollable(true).
		SetChangedFunc(func() {
			t.App.Draw()
		})
	t.ChatView.SetBorder(true).SetTitle("Chat")

	t.StatusView = tview.NewTextView().SetDynamicColors(true)
	t.StatusView.SetText("Status: Online (Ctrl+A: Add Friend, /safety, /remove <id>, Ctrl+I: Invites, Ctrl+F: Send File, Ctrl+P: Call/Hangup, Tab: Switch, /quit)")

	t.FriendsList = tview.NewList().ShowSecondaryText(false)
	t.FriendsList.SetBorder(true).SetTitle("Friends & Groups")

	t.InputField = tview.NewInputField().SetLabel("Msg: ").SetFieldWidth(0)

	// Detect Typing Input
	t.InputField.SetChangedFunc(func(text string) {
		if t.ActiveID != "LOG" && text != "" && !strings.HasPrefix(t.ActiveID, "G-") {
			// Debounce: Only send every 2 seconds
			if time.Since(t.lastTyped) > 2*time.Second {
				t.lastTyped = time.Now()
				go t.Client.SendTyping(context.Background(), t.ActiveID)
			}
		}
	})

	t.InputField.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			text := t.InputField.GetText()
			if text != "" {
				t.handleInput(text)
				t.InputField.SetText("")
			}
		}
	})

	flex := tview.NewFlex().
		AddItem(t.FriendsList, 20, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(t.ChatView, 0, 1, false).
			AddItem(t.StatusView, 1, 1, false).
			AddItem(t.InputField, 3, 1, true), 0, 3, true)

	t.Pages = tview.NewPages()
	t.Pages.AddPage("main", flex, true, true)
	t.App.SetRoot(t.Pages, true).SetFocus(t.InputField)

	// Main App Input Capture (overrides the initial one from client.go)
	t.App.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyCtrlA {
			t.showAddFriendForm()
			return nil
		}

		if event.Key() == tcell.KeyCtrlN {
			t.showPendingInvites()
			return nil
		}

		if event.Key() == tcell.KeyCtrlF {
			t.showSendFileForm()
			return nil
		}

		// Ensure Ctrl+C still quits here
		if event.Key() == tcell.KeyCtrlC {
			t.App.Stop()
			return nil
		}

		if event.Key() == tcell.KeyCtrlP {
			if t.Client.Voice.Active() {
				go t.Client.HangupCall()
			} else if t.ActiveID != "LOG" {
				go func() {
					if err := t.Client.InviteCall(t.ActiveID); err != nil {
						t.OnLog("[red]Call Failed: %v[-]\n", err)
					} else {
						t.OnLog("[yellow]Calling...[-]\n")
					}
				}()
			}
			return nil
		}

		if event.Key() == tcell.KeyTab {
			focus := t.App.GetFocus()
			switch focus {
			case t.FriendsList:
				t.App.SetFocus(t.InputField)
				return nil
			case t.InputField:
				t.App.SetFocus(t.FriendsList)
				return nil
			}
			return event
		}
		return event
	})
}

func (t *TUI) appendToBuffer(id, msg string) {
	t.bufferMu.Lock()
	t.ChatBuffers[id] += msg
	content := t.ChatBuffers[id]
	t.bufferMu.Unlock()

	if t.ActiveID == id {
		t.ChatView.SetText(content)
		t.ChatView.ScrollToEnd()
	}
}

func (t *TUI) refreshFriends() {
	t.FriendsList.Clear()

	t.FriendsList.AddItem("System", "", 0, func() {
		t.ActiveID = "LOG"
		t.bufferMu.RLock()
		content := t.ChatBuffers["LOG"]
		t.bufferMu.RUnlock()

		t.ChatView.SetText(content)
		t.ChatView.ScrollToEnd()
		t.updateStatusText()
		t.App.SetFocus(t.InputField)
	})

	// Add Groups
	groups := t.Client.Profile.ListGroups()
	for _, g := range groups {
		label := fmt.Sprintf("[blue]G: %s[-]", g.Name)
		gid := g.ID
		t.FriendsList.AddItem(label, "", 0, func() {
			t.ActiveID = gid
			t.bufferMu.Lock()
			if _, ok := t.ChatBuffers[gid]; !ok {
				t.ChatBuffers[gid] = ""
			}
			content := t.ChatBuffers[gid]
			t.bufferMu.Unlock()
			t.ChatView.SetText(content)
			t.ChatView.ScrollToEnd()
			t.updateStatusText()
			t.App.SetFocus(t.InputField)
		})
	}

	// Add Friends
	friends := t.Client.Profile.ListFriends()
	for _, f := range friends {
		status := "[gray]Offline[-]"
		if _, online := t.Client.Peer.GetSession(f.ID); online {
			status = "[green]Online[-]"
		}

		// Verified indicator
		verifiedMark := ""
		if f.Verified {
			verifiedMark = "[green][V][-]"
		}

		label := fmt.Sprintf("%s%s %s", f.Name, verifiedMark, status)
		friendID := f.ID

		t.FriendsList.AddItem(label, "", 0, func() {
			t.ActiveID = friendID
			t.bufferMu.Lock()
			if _, ok := t.ChatBuffers[friendID]; !ok {
				t.ChatBuffers[friendID] = ""
			}
			content := t.ChatBuffers[friendID]
			t.bufferMu.Unlock()

			t.ChatView.SetText(content)
			t.ChatView.ScrollToEnd()
			t.updateStatusText()
			t.App.SetFocus(t.InputField)
		})
	}
}

// Centralized Status Bar Updater
func (t *TUI) updateStatusText() {
	voiceStatus := "[gray]No Call[-]"
	if t.Client.Voice.Active() {
		muteTag := ""
		if t.Client.Voice.IsMuted() {
			muteTag = " [red](MUTED)[-]"
		}
		voiceStatus = fmt.Sprintf("[red]📞 CALL: %s[-]%s", t.Client.Voice.GetTargetID(), muteTag)
	}

	if t.ActiveID == "LOG" {
		t.StatusView.SetText(fmt.Sprintf("Channel: System | %s", voiceStatus))
		return
	}

	name := t.Client.Peer.GetName(t.ActiveID)

	// Handle Group display name
	if strings.HasPrefix(t.ActiveID, "G-") {
		if g, ok := t.Client.Profile.GetGroup(t.ActiveID); ok {
			name = g.Name
		} else {
			name = "Unknown Group"
		}
	} else {
		// Peer: Check verification
		if f, ok := t.Client.Profile.GetFriend(t.ActiveID); ok {
			// Always prefer the name from the local Profile for friends.
			// The Peer layer alias might be missing (just ID) if recently connected.
			if f.Name != "" {
				name = f.Name
			}

			if f.Verified {
				name += " [green](Verified)[-]"
			} else {
				name += " [red](Unverified)[-]"
			}
		}
	}

	base := fmt.Sprintf("Texting: [yellow]%s[-]", name)

	// Check Typing
	typingStatus := ""
	if _, ok := t.typingTimers[t.ActiveID]; ok {
		typingStatus = " [blue]...typing...[-]"
	}

	t.StatusView.SetText(fmt.Sprintf("%s%s | %s", base, typingStatus, voiceStatus))
}