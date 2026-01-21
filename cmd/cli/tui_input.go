package main

import (
	"context"
	"fmt"
	"strings"
)

func (t *TUI) handleInput(text string) {
	if strings.HasPrefix(text, "/") {
		parts := strings.Fields(text)
		if len(parts) > 0 {
			switch parts[0] {
			case "/invite":
				if len(parts) > 1 {
					t.Client.SendInvite(context.Background(), parts[1])
					t.appendToBuffer("LOG", fmt.Sprintf("[green]Invite sent to ID: %s[-]\n", parts[1]))
				} else {
					t.appendToBuffer("LOG", "[red]Usage: /invite <user_id>[-]\n")
				}
			case "/accept":
				if len(parts) > 1 {
					go func(targetID string) {
						t.Client.AcceptInvite(context.Background(), targetID)
					}(parts[1])
				} else {
					t.appendToBuffer("LOG", "[red]Usage: /accept <user_id>[-]\n")
				}

			case "/remove":
				if len(parts) > 1 {
					targetID := parts[1]
					go func() {
						// Confirm existence first
						if _, ok := t.Client.Profile.GetFriend(targetID); !ok {
							t.App.QueueUpdateDraw(func() {
								t.appendToBuffer("LOG", fmt.Sprintf("[red]Friend %s not found.[-]\n", targetID))
							})
							return
						}

						if err := t.Client.RemoveFriend(targetID); err != nil {
							t.OnLog("[red]Failed to remove friend: %v[-]\n", err)
						} else {
							t.OnLog("[green]Removed friend %s[-]\n", targetID)
							t.App.QueueUpdateDraw(func() {
								t.refreshFriends()
								// If we were active on the removed friend, switch to LOG
								if t.ActiveID == targetID {
									t.ActiveID = "LOG"
									// Force immediate update of chat view to LOG
									t.bufferMu.RLock()
									content := t.ChatBuffers["LOG"]
									t.bufferMu.RUnlock()
									t.ChatView.SetText(content)
									t.updateStatusText()
								}
							})
						}
					}()
				} else {
					t.appendToBuffer("LOG", "[red]Usage: /remove <user_id>[-]\n")
				}
				
			case "/safety", "/verify":
				if t.ActiveID == "LOG" || strings.HasPrefix(t.ActiveID, "G-") {
					t.appendToBuffer("LOG", "[red]Select a friend first to view safety number.[-]\n")
					return
				}
				t.showSafetyNumberModal(t.ActiveID)
			
			case "/metrics":
				t.showMetricsModal()

			// Group Commands
			case "/group":
				if len(parts) < 2 {
					t.appendToBuffer("LOG", "[red]Usage: /group <create|list|add|leave|kick|invite> ...[-]\n")
					return
				}
				cmd := parts[1]
				switch cmd {
				case "create":
					// /group create <Name> <ID1> <ID2>...
					if len(parts) < 3 {
						t.appendToBuffer("LOG", "[red]Usage: /group create <Name> <MemberID1> ...[-]\n")
						return
					}
					name := parts[2]
					members := parts[3:]
					go func() {
						gid, err := t.Client.CreateGroup(name, members)
						if err != nil {
							t.OnLog("[red]Failed to create group: %v[-]\n", err)
						} else {
							t.OnLog("[green]Group '%s' created (ID: %s)[-]\n", name, gid)
							t.App.QueueUpdateDraw(func() { t.refreshFriends() })
						}
					}()

				case "list":
					groups := t.Client.Profile.ListGroups()
					for _, g := range groups {
						t.appendToBuffer("LOG", fmt.Sprintf("[blue]Group '%s' (ID: %s) Members: %d[-]\n", g.Name, g.ID, len(g.Members)))
					}

				case "invite":
					// /group invite <GID> <UserID> [UserID...]
					if len(parts) < 4 {
						t.appendToBuffer("LOG", "[red]Usage: /group invite <GroupID> <UserID> ...[-]\n")
						return
					}
					gid := parts[2]
					uids := parts[3:]
					go func() {
						// Confirm group existence
						if _, ok := t.Client.Profile.GetGroup(gid); !ok {
							t.App.QueueUpdateDraw(func() {
								t.appendToBuffer("LOG", fmt.Sprintf("[red]Group %s not found.[-]\n", gid))
							})
							return
						}

						t.Client.InviteToGroup(gid, uids)
						t.OnLog("[green]Invites sent to %v for group %s[-]\n", uids, gid)
					}()

				case "add":
					// /group add <GID> <UserID>
					if len(parts) < 4 {
						t.appendToBuffer("LOG", "[red]Usage: /group add <GroupID> <UserID>[-]\n")
						return
					}
					gid := parts[2]
					uid := parts[3]
					go func() {
						if err := t.Client.AddUserToGroup(context.Background(), gid, uid); err != nil {
							t.OnLog("[red]Failed to add user: %v[-]\n", err)
						} else {
							t.OnLog("[green]Added user %s to group %s[-]\n", uid, gid)
						}
					}()
				case "leave":
					// /group leave <GID>
					if len(parts) < 3 {
						t.appendToBuffer("LOG", "[red]Usage: /group leave <GroupID>[-]\n")
						return
					}
					gid := parts[2]
					go func() {
						if err := t.Client.LeaveGroup(context.Background(), gid); err != nil {
							t.OnLog("[red]Failed to leave group: %v[-]\n", err)
						} else {
							t.OnLog("[green]Left group %s[-]\n", gid)
							// Refresh list to remove the group from the UI Sidebar
							t.App.QueueUpdateDraw(func() { t.refreshFriends() })
							// If we were looking at that group, switch back to LOG
							if t.ActiveID == gid {
								t.ActiveID = "LOG"
								t.App.QueueUpdateDraw(func() { t.refreshFriends() })
							}
						}
					}()
				case "kick":
					// /group kick <GID> <UserID>
					if len(parts) < 4 {
						t.appendToBuffer("LOG", "[red]Usage: /group kick <GroupID> <UserID>[-]\n")
						return
					}
					gid := parts[2]
					uid := parts[3]
					go func() {
						if err := t.Client.KickUserFromGroup(context.Background(), gid, uid); err != nil {
							t.OnLog("[red]Failed to kick user: %v[-]\n", err)
						} else {
							t.OnLog("[green]User %s removed from group %s[-]\n", uid, gid)
						}
					}()
				default:
					t.appendToBuffer("LOG", "[red]Unknown group command[-]\n")
				}

			case "/devices":
				t.showDeviceSelector()

			case "/sendfile":
				if t.ActiveID == "LOG" {
					t.appendToBuffer("LOG", "[red]Select a friend to send a file to first.[-]\n")
					return
				}
				if len(parts) < 2 {
					t.appendToBuffer("LOG", "[red]Usage: /sendfile <filepath>[-]\n")
					return
				}
				path := strings.Join(parts[1:], " ")
				go func(targetID, fpath string) {
					err := t.Client.SendFile(context.Background(), targetID, fpath)
					if err != nil {
						t.App.QueueUpdateDraw(func() {
							t.appendToBuffer("LOG", fmt.Sprintf("[red]File transfer failed: %v[-]\n", err))
						})
					}
				}(t.ActiveID, path)

			case "/call":
				// Handle: /call add <ID>
				if len(parts) > 2 && parts[1] == "add" {
					targetID := parts[2]
					go func() {
						if err := t.Client.InviteCall(targetID); err != nil {
							t.OnLog("[red]Add User Failed: %v[-]\n", err)
						} else {
							t.OnLog("[yellow]Inviting %s to call...[-]\n", targetID)
						}
					}()
					return
				}

				// Normal Call
				targetID := t.ActiveID
				if targetID == "LOG" {
					t.appendToBuffer("LOG", "[red]Select a friend to call[-]\n")
					return
				}

				if t.Client.Voice.Active() {
					t.appendToBuffer("LOG", "[red]Call already active. Use '/call add <ID>' to add user.[-]\n")
				} else {
					go func() {
						if err := t.Client.InviteCall(targetID); err != nil {
							t.OnLog("[red]Call Failed: %v[-]\n", err)
						} else {
							t.OnLog("[yellow]Calling...[-]\n")
						}
					}()
				}

			case "/hangup":
				go func() {
					if t.Client.Voice.Active() {
						t.Client.HangupCall()
					} else {
						t.App.QueueUpdateDraw(func() {
							t.appendToBuffer("LOG", "[red]No active call[-]\n")
						})
					}
				}()

			case "/mute":
				go func() {
					isMuted := t.Client.ToggleMute()

					statusMsg := "[green]Microphone Unmuted[-]"
					if isMuted {
						statusMsg = "[red]Microphone Muted[-]"
					}

					t.App.QueueUpdateDraw(func() {
						t.appendToBuffer("LOG", statusMsg+"\n")
						t.updateStatusText() // Refresh status bar
					})
				}()

			case "/password":
				if len(parts) == 1 {
					t.appendToBuffer("LOG", "[red]Encryption cannot be disabled.[-]\n")
				} else {
					newPw := strings.Join(parts[1:], " ")
					t.Client.Profile.SetPassword(newPw)
					if err := t.Client.Profile.Save(); err != nil {
						t.appendToBuffer("LOG", fmt.Sprintf("[red]Failed to save profile: %v[-]\n", err))
					} else {
						t.appendToBuffer("LOG", "[green]Password set. Profile encrypted.[-]\n")
					}
				}

			case "/quit":
				t.App.Stop()

			default:
				t.appendToBuffer("LOG", "[red]Unknown command[-]\n")
			}
		}
		return
	}
	if t.ActiveID != "LOG" {
		// Capture variables for the goroutine
		targetID := t.ActiveID
		msgContent := text

		// Detect if target is Group or Peer
		go func() {
			if strings.HasPrefix(targetID, "G-") {
				if err := t.Client.SendGroupText(context.Background(), targetID, msgContent); err != nil {
					t.OnLog("[red]Group send failed: %v[-]\n", err)
				}
			} else {
				if err := t.Client.SendText(context.Background(), targetID, msgContent); err != nil {
					t.OnLog("[red]Delivery failed: %v[-]\n", err)
				}
			}
		}()

		// 2. Update UI immediately (Optimistic)
		t.appendToBuffer(t.ActiveID, fmt.Sprintf("[yellow]Me[-]: %s\n", text))
	} else {
		t.appendToBuffer("LOG", "[red]Select a friend to chat[-]\n")
	}
}