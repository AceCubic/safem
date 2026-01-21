package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/banditmoscow1337/safem/protocol/profile"
	"github.com/rivo/tview"
)

func (t *TUI) OnLog(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)

	// Temporary: Write system logs to file
	func() {
		f, err := os.OpenFile("debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return
		}
		defer f.Close()

		timestamp := time.Now().Format("15:04:05.000")
		// Write raw message
		if len(msg) > 0 && msg[len(msg)-1] != '\n' {
			fmt.Fprintf(f, "[%s] %s\n", timestamp, msg)
		} else {
			fmt.Fprintf(f, "[%s] %s", timestamp, msg)
		}
	}()

	t.App.QueueUpdateDraw(func() {
		t.appendToBuffer("LOG", fmt.Sprintf("[gray]%s[-]", msg))
	})
}

func (t *TUI) OnMessage(id, name, text string) {
	t.App.QueueUpdateDraw(func() {
		// Clear typing indicator on message receive
		if timer, ok := t.typingTimers[id]; ok {
			timer.Stop()
			delete(t.typingTimers, id)
			t.updateStatusText()
		}

		formatted := fmt.Sprintf("[red]%s[-]: %s\n", name, text)
		t.appendToBuffer(id, formatted)
		if id != t.ActiveID {
			t.appendToBuffer("LOG", fmt.Sprintf("[gray]New message from %s[-]\n", name))
		}
	})
}

// OnTyping Implementation
func (t *TUI) OnTyping(id string) {
	t.App.QueueUpdateDraw(func() {
		// If timer exists, stop it (refresh)
		if timer, ok := t.typingTimers[id]; ok {
			timer.Stop()
		}

		// Set new timer to clear typing status after 3 seconds
		t.typingTimers[id] = time.AfterFunc(3*time.Second, func() {
			t.App.QueueUpdateDraw(func() {
				delete(t.typingTimers, id)
				t.updateStatusText()
			})
		})

		t.updateStatusText()
	})
}

func (t *TUI) OnInviteReceived(id, name, addr, pem string) {
	t.App.QueueUpdateDraw(func() {
		// Log the event so it remains in history
		t.appendToBuffer("LOG", fmt.Sprintf("[gray]📩 Invite received from %s (%s)[-]\n", name, id))

		pageName := fmt.Sprintf("invite_modal_%s", id)

		modal := tview.NewModal().
			SetText(fmt.Sprintf("Friend Request\n\nFrom: %s\nID: %s", name, id)).
			AddButtons([]string{"Accept", "Reject"}).
			SetDoneFunc(func(buttonIndex int, buttonLabel string) {
				// Update UI immediately
				t.Pages.RemovePage(pageName)
				t.App.SetFocus(t.InputField)

				// Handle Action
				if buttonLabel == "Accept" {
					go func() {
						t.Client.AcceptInvite(context.Background(), id)
					}()
				} else {
					t.OnLog("[gray]Invite from %s ignored.[-]\n", name)
				}
			})

		t.Pages.AddPage(pageName, modal, false, true)
	})
}

func (t *TUI) OnFriendAdded(id, name string) {
	t.OnLog("Friend added: %s (%s)\n", name, id)
	t.App.QueueUpdateDraw(func() {
		t.refreshFriends()
	})
}

func (t *TUI) OnFriendStatus(id string, online bool) {
	t.App.QueueUpdateDraw(func() {
		t.refreshFriends()
	})
}

// OnFriendUpdated handles profile content updates (e.g. status text changed)
func (t *TUI) OnFriendUpdated(id string, info profile.UserContent) {
	t.App.QueueUpdateDraw(func() {
		name := "Unknown"
		if t.Client != nil && t.Client.Peer != nil {
			name = t.Client.Peer.GetName(id)
		}
		
		status := info.TextStatus
		if status == "" {
			status = "Updated"
		}
		
		// Log the update minimally
		t.appendToBuffer("LOG", fmt.Sprintf("[gray][Sync] Profile updated for %s: %s[-]\n", name, status))
		
		// Refresh list to update any UI elements relying on content
		t.refreshFriends()
	})
}

func (t *TUI) OnVoiceStatus(active bool, targetName string) {
	t.App.QueueUpdateDraw(func() {
		t.updateStatusText()
	})
}

func (t *TUI) OnFileReceived(id, name, path string) {
	t.App.QueueUpdateDraw(func() {
		t.appendToBuffer(id, fmt.Sprintf("[blue]Received file: %s (Saved as %s)[-]\n", name, path))
	})
}

// Modal for Incoming File Requests
func (t *TUI) OnFileRequest(transferID, senderID, name string, size int64) {
	senderName := t.Client.Peer.GetName(senderID)
	
	t.App.QueueUpdateDraw(func() {
		// Generate unique page name
		pageName := fmt.Sprintf("file_req_%s", transferID)

		modal := tview.NewModal().
			SetText(fmt.Sprintf("File Request from %s\n\nFile: %s\nSize: %.2f MB\n\nDo you want to accept this file?", senderName, name, float64(size)/1024/1024)).
			AddButtons([]string{"Accept", "Reject"}).
			SetDoneFunc(func(buttonIndex int, buttonLabel string) {
				// Remove Modal
				t.Pages.RemovePage(pageName)
				t.App.SetFocus(t.InputField)

				if buttonLabel == "Accept" {
					go func() {
						if err := t.Client.AcceptFileTransfer(transferID); err != nil {
							t.OnLog("[red]Failed to accept file: %v[-]\n", err)
						}
					}()
				} else {
					go t.Client.RejectFileTransfer(transferID)
				}
			})

		t.Pages.AddPage(pageName, modal, false, true)
	})
}

func (t *TUI) OnIncomingCall(id, name string) {
	t.App.QueueUpdateDraw(func() {
		modal := tview.NewModal().
			SetText(fmt.Sprintf("Incoming Call from %s", name)).
			AddButtons([]string{"Accept", "Reject"}).
			SetDoneFunc(func(buttonIndex int, buttonLabel string) {
				// Update UI immediately (Main Thread)
				t.Pages.RemovePage("call_modal")
				t.App.SetFocus(t.InputField)

				// Run blocking logic in background (Goroutine)
				go func() {
					if buttonLabel == "Accept" {
						t.Client.AnswerCall(id, true)
					} else {
						t.Client.AnswerCall(id, false)
					}
				}()
			})

		t.Pages.AddPage("call_modal", modal, false, true)
	})
}