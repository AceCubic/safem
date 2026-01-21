package main

import (
	"context"
	"fmt"
	"sort"

	"github.com/banditmoscow1337/safem/protocol/server"
	"github.com/gen2brain/malgo"
	"github.com/rivo/tview"
)

func (t *TUI) showNicknameForm(onDone func()) {
	var nick string
	var serverToken string
	var password string

	form := tview.NewForm().
		AddInputField("Enter Nickname", "", 20, nil, func(text string) {
			nick = text
		}).
		AddInputField("Server Token", "", 0, nil, func(text string) {
			serverToken = text
		})
	
	// Password is now mandatory
	form.AddInputField("Profile Password", "", 20, nil, func(text string) {
		password = text
	})

	form.AddButton("Start Chatting", func() {
			n := nick
			st := serverToken
			pw := password

			// Validation: Password must not be empty
			if pw == "" {
				// Update directly on UI thread to avoid deadlock/freeze from QueueUpdateDraw
				form.SetTitle(" [red]Error: Password Required[-]")
				return
			}

			go func() {
				if n == "" {
					n = "User"
				}
				t.Client.Profile.SetNickname(n)

				if st != "" {
					token, err := server.DecodeServerToken(st)
					if err == nil {
						// Set Server Enc PEM
						t.Client.Profile.SetServer(token.Addr, token.PEM, token.EncPEM)
					} else {
						t.App.QueueUpdateDraw(func() {
							t.OnLog("[red]Invalid Server Token ignored: %v[-]\n", err)
						})
					}
				}

				t.Client.Profile.SetPassword(pw)

				// Check for save errors (e.g. key generation issues)
				if err := t.Client.Profile.Save(); err != nil {
					t.App.QueueUpdateDraw(func() {
						form.SetTitle(fmt.Sprintf(" [red]Error Saving: %v[-]", err))
					})
					return
				}

				t.App.QueueUpdateDraw(func() {
					t.Pages.RemovePage("nickname_form")
					t.App.SetFocus(t.InputField)
					
					if onDone != nil {
						onDone()
					}
				})
			}()
		})

	form.SetBorder(true).SetTitle(" Welcome ").SetTitleAlign(tview.AlignCenter)

	modal := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(form, 16, 1, true). 
			AddItem(nil, 0, 1, false), 50, 1, true). 
		AddItem(nil, 0, 1, false)

	t.Pages.AddPage("nickname_form", modal, true, true)
}

func (t *TUI) showUnlockForm(validator func(string) error) {
	var password string
	form := tview.NewForm().
		AddInputField("Password", "", 20, nil, func(text string) {
			password = text
		})
	

	form.AddButton("Unlock", func() {
		// Capture variable
		pw := password
		go func() {
			if err := validator(pw); err != nil {
				t.App.QueueUpdateDraw(func() {
					form.SetTitle(fmt.Sprintf(" [red]Error: %v[-]", err))
				})
			} else {
				// Success is handled by the validator callback (changing pages/setup)
				t.App.QueueUpdateDraw(func() {
					t.Pages.RemovePage("unlock_form")
				})
			}
		}()
	})

	form.AddButton("Quit", func() {
		t.App.Stop()
	})

	form.SetBorder(true).SetTitle(" Profile Locked ").SetTitleAlign(tview.AlignCenter)

	modal := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(form, 10, 1, true).
			AddItem(nil, 0, 1, false), 50, 1, true).
		AddItem(nil, 0, 1, false)

	t.Pages.AddPage("unlock_form", modal, true, true)
}

func (t *TUI) showAddFriendForm() {
	var userID string
	form := tview.NewForm().
		AddInputField("User ID", "", 40, nil, func(text string) {
			userID = text
		}).
		AddButton("Invite", func() {
			targetID := userID
			go func() {
				if targetID != "" {
					t.Client.SendInvite(context.Background(), targetID)
					t.App.QueueUpdateDraw(func() {
						t.appendToBuffer("LOG", fmt.Sprintf("[green]Invite sent to ID: %s[-]\n", targetID))
					})
				}
				t.App.QueueUpdateDraw(func() {
					t.Pages.RemovePage("add_friend")
					t.App.SetFocus(t.InputField)
				})
			}()
		}).
		AddButton("Cancel", func() {
			t.Pages.RemovePage("add_friend")
			t.App.SetFocus(t.InputField)
		})
	form.SetBorder(true).SetTitle(" Add Friend (Enter ID) ").SetTitleAlign(tview.AlignCenter)

	modal := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(form, 10, 1, true).
			AddItem(nil, 0, 1, false), 50, 1, true).
		AddItem(nil, 0, 1, false)
	t.Pages.AddPage("add_friend", modal, true, true)
}

func (t *TUI) showSafetyNumberModal(targetID string) {
	name := t.Client.Peer.GetName(targetID)
	safetyNum, err := t.Client.GetSafetyNumber(targetID)
	if err != nil {
		t.OnLog("[red]Error computing safety number: %v[-]\n", err)
		return
	}

	// Split number for display readability
	formatted := fmt.Sprintf("%s\n%s", safetyNum[:17], safetyNum[18:])

	isVerified := false
	if f, ok := t.Client.Profile.GetFriend(targetID); ok {
		isVerified = f.Verified
	}

	statusText := "[red]Not Verified[-]"
	verifyBtnLabel := "Mark Verified"
	
	if isVerified {
		statusText = "[green]Verified[-]"
		verifyBtnLabel = "Un-Verify"
	}

	modal := tview.NewModal().
		SetText(fmt.Sprintf("Safety Number for %s\n\n%s\n\nStatus: %s\n\nCompare this number with your friend to ensure\nno Man-in-the-Middle attack is occurring.", name, formatted, statusText)).
		AddButtons([]string{verifyBtnLabel, "Close"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			t.Pages.RemovePage("safety_number")
			t.App.SetFocus(t.InputField)

			if buttonLabel == "Close" {
				return
			}

			// Run in background to avoid blocking UI thread with Profile locks
			go func() {
				switch buttonLabel {
				case "Mark Verified":
					t.Client.Profile.SetFriendVerified(targetID, true)
					t.OnLog("[green]Marked %s as Verified.[-]\n", name)
				case "Un-Verify":
					t.Client.Profile.SetFriendVerified(targetID, false)
					t.OnLog("[yellow]Marked %s as NOT Verified.[-]\n", name)
				}

				// Refresh UI (Must be on UI thread)
				t.App.QueueUpdateDraw(func() {
					t.refreshFriends()
					t.updateStatusText() // Explicitly update status bar
				})

				// Save to disk
				t.Client.Profile.Save()
			}()
		})

	t.Pages.AddPage("safety_number", modal, false, true)
}

func (t *TUI) showDeviceSelector() {
	captureDevs, playbackDevs, err := t.Client.Voice.Engine.ListDevices() // Updated
	if err != nil {
		t.appendToBuffer("LOG", fmt.Sprintf("[red]Error listing devices: %v[-]\n", err))
		return
	}

	inputOpts := []string{"Default"}
	outputOpts := []string{"Default"}

	for _, d := range captureDevs {
		inputOpts = append(inputOpts, d.Name())
	}
	for _, d := range playbackDevs {
		outputOpts = append(outputOpts, d.Name())
	}

	var selectedInputIdx, selectedOutputIdx int

	form := tview.NewForm().
		AddDropDown("Input Device", inputOpts, 0, func(option string, optionIndex int) {
			selectedInputIdx = optionIndex
		}).
		AddDropDown("Output Device", outputOpts, 0, func(option string, optionIndex int) {
			selectedOutputIdx = optionIndex
		}).
		AddButton("Save & Restart Audio", func() {
			// Capture indices
			inIdx := selectedInputIdx
			outIdx := selectedOutputIdx
			
			go func() {
				var inputID *malgo.DeviceID
				if inIdx > 0 && inIdx-1 < len(captureDevs) {
					id := captureDevs[inIdx-1].ID
					inputID = &id
				}

				var outputID *malgo.DeviceID
				if outIdx > 0 && outIdx-1 < len(playbackDevs) {
					id := playbackDevs[outIdx-1].ID
					outputID = &id
				}

				t.Client.Voice.Engine.SetInputDevice(inputID)
				t.Client.Voice.Engine.SetOutputDevice(outputID)

				if err := t.Client.Voice.Engine.Restart(); err != nil {
					t.App.QueueUpdateDraw(func() {
						t.appendToBuffer("LOG", fmt.Sprintf("[red]Audio restart failed: %v[-]\n", err))
					})
				} else {
					t.App.QueueUpdateDraw(func() {
						t.appendToBuffer("LOG", "[green]Audio devices updated.[-]\n")
					})
				}

				t.App.QueueUpdateDraw(func() {
					t.Pages.RemovePage("devices")
					t.App.SetFocus(t.InputField)
				})
			}()
		}).
		AddButton("Cancel", func() {
			t.Pages.RemovePage("devices")
			t.App.SetFocus(t.InputField)
		})

	form.SetBorder(true).SetTitle(" Audio Settings ").SetTitleAlign(tview.AlignCenter)

	modal := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(form, 14, 1, true).
			AddItem(nil, 0, 1, false), 60, 1, true).
		AddItem(nil, 0, 1, false)

	t.Pages.AddPage("devices", modal, true, true)
}

func (t *TUI) showSendFileForm() {
	if t.ActiveID == "LOG" {
		t.appendToBuffer("LOG", "[red]Select a friend to send a file to first.[-]\n")
		return
	}

	var filePath string
	form := tview.NewForm().
		AddInputField("File Path", "", 40, nil, func(text string) {
			filePath = text
		}).
		AddButton("Send", func() {
			path := filePath
			targetID := t.ActiveID
			go func() {
				if path != "" {
					err := t.Client.SendFile(context.Background(), targetID, path)
					if err != nil {
						t.App.QueueUpdateDraw(func() {
							t.appendToBuffer("LOG", fmt.Sprintf("[red]File transfer failed: %v[-]\n", err))
						})
					}
				}
				t.App.QueueUpdateDraw(func() {
					t.Pages.RemovePage("send_file")
					t.App.SetFocus(t.InputField)
				})
			}()
		}).
		AddButton("Cancel", func() {
			t.Pages.RemovePage("send_file")
			t.App.SetFocus(t.InputField)
		})

	targetName := t.Client.Peer.GetName(t.ActiveID)
	form.SetBorder(true).SetTitle(fmt.Sprintf(" Send File to %s ", targetName)).SetTitleAlign(tview.AlignCenter)

	modal := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(form, 10, 1, true).
			AddItem(nil, 0, 1, false), 60, 1, true).
		AddItem(nil, 0, 1, false)

	t.Pages.AddPage("send_file", modal, true, true)
}

func (t *TUI) showPendingInvites() {
	t.Client.Peer.KeysMu.RLock()
	if len(t.Client.Peer.PendingInvites) == 0 {
		t.Client.Peer.KeysMu.RUnlock()
		t.appendToBuffer("LOG", "[gray]No pending invites.[-]\n")
		return
	}
	
	// Collect IDs to list for stable ordering
	var ids []string
	for id := range t.Client.Peer.PendingInvites {
		ids = append(ids, id)
	}
	t.Client.Peer.KeysMu.RUnlock()
	sort.Strings(ids)

	list := tview.NewList().ShowSecondaryText(true)
	list.SetBorder(true).SetTitle(" Pending Invites (Enter to Accept) ").SetTitleAlign(tview.AlignCenter)

	for _, id := range ids {
		name := t.Client.Peer.GetName(id)
		// Capture variable for closure
		targetID := id 
		targetName := name
		
		list.AddItem(targetName, fmt.Sprintf("ID: %s", targetID), 0, func() {
			// On Select: Show Confirmation Modal
			confirmModal := tview.NewModal().
				SetText(fmt.Sprintf("Accept friend request from %s?", targetName)).
				AddButtons([]string{"Accept", "Reject", "Cancel"}).
				SetDoneFunc(func(buttonIndex int, buttonLabel string) {
					t.Pages.RemovePage("confirm_invite")
					
					switch buttonLabel {
					case "Accept":
						go t.Client.AcceptInvite(context.Background(), targetID)
					case "Reject":
						// Remove from pending without accepting
						t.Client.Peer.KeysMu.Lock()
						delete(t.Client.Peer.PendingInvites, targetID)
						t.Client.Peer.KeysMu.Unlock()
						t.OnLog("[gray]Invite from %s rejected.[-]\n", targetName)
					}
					// Remove the list page as well
					t.Pages.RemovePage("pending_invites")
					t.App.SetFocus(t.InputField)
				})
			t.Pages.AddPage("confirm_invite", confirmModal, false, true)
		})
	}

	modal := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(list, 20, 1, true).
			AddItem(nil, 0, 1, false), 60, 1, true).
		AddItem(nil, 0, 1, false)

	t.Pages.AddPage("pending_invites", modal, true, true)
}

func (t *TUI) showMetricsModal() {
	dropped := t.Client.Peer.PacketsDropped.Load()
	retrans := t.Client.Peer.Retransmits.Load()
	starvation := t.Client.Peer.PoolStarvation.Load()

	text := fmt.Sprintf("Network Metrics\n\nPackets Dropped: %d\nRetransmits: %d\nPool Starvation: %d", dropped, retrans, starvation)

	modal := tview.NewModal().
		SetText(text).
		AddButtons([]string{"Refresh", "Close"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			if buttonLabel == "Refresh" {
				// Re-open to refresh the data
				t.Pages.RemovePage("metrics_modal")
				t.showMetricsModal()
			} else {
				t.Pages.RemovePage("metrics_modal")
				t.App.SetFocus(t.InputField)
			}
		})

	t.Pages.AddPage("metrics_modal", modal, false, true)
}