package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/banditmoscow1337/safem/protocol/client"
	"github.com/banditmoscow1337/safem/protocol/cryptolib"
	"github.com/banditmoscow1337/safem/protocol/profile"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/term"
)

// LogFunc matches the signature for the custom logger used in the application
type LogFunc func(format string, args ...any)

func main() {
	if !checkLibOpus() {
		if err := installLibOpus(); err != nil {
			log.Fatal(err)
		}
	}

	tui := &TUI{
		App:         tview.NewApplication(),
		Pages:       tview.NewPages(),
		ChatBuffers: make(map[string]string),
		ActiveID:    "LOG",
		bufferMu:    sync.RWMutex{},
	}

	// GLOBAL INPUT CAPTURE (Initial)
	// This ensures Ctrl+C works immediately, even on the Login/Unlock screens
	// before setupLayout() is called.
	tui.App.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyCtrlC {
			tui.App.Stop()
			return nil
		}
		return event
	})

	tui.App.SetRoot(tui.Pages, true)

	initializeApp := func(prof *profile.Profile) {
		if !prof.HasIdentity() {
			priv, pub, _ := cryptolib.GenerateKeyPair(0)
			encPriv, encPub, _ := cryptolib.GenerateECDH()

			prof.SetIdentity(
				client.StorePrivateKey(priv),
				cryptolib.PubKeyToPEM(pub),
				cryptolib.EncPrivateKeyToPEM(encPriv),
				cryptolib.EncPubKeyToPEM(encPub),
			)
			prof.Save()
		}

		cli, err := client.New(prof, tui)
		if err != nil {
			log.Fatal(err)
		}
		tui.Client = cli

		tui.setupLayout()

		tui.bufferMu.Lock()
		tui.ChatBuffers["LOG"] = ""

		myID := prof.GetID()

		for peerID, msgs := range prof.GetHistorySnapshot() {
			var sb strings.Builder
			for _, msg := range msgs {
				var name, color string
				if msg.SenderID == myID {
					name = "Me"
					color = "yellow"
				} else {
					if f, ok := prof.GetFriend(msg.SenderID); ok {
						name = f.Name
					} else {
						name = "Unknown"
					}
					color = "red"
				}
				fmt.Fprintf(&sb, "[%s]%s[-]: %s\n", color, name, msg.Content)
			}
			tui.ChatBuffers[peerID] = sb.String()
		}
		tui.bufferMu.Unlock()

		startConnection := func() {
			addr, err := cli.Start()
			if err != nil {
				tui.appendToBuffer("LOG", fmt.Sprintf("[red]Start error: %v[-]\n", err))
			} else {
				tui.appendToBuffer("LOG", fmt.Sprintf("[green]Online at %s[-]\n", addr))
				tui.appendToBuffer("LOG", fmt.Sprintf("[green]Your ID: %s[-]\n", cli.Profile.GetID()))

				go func() {
					time.Sleep(100 * time.Millisecond)

					srvAddr, srvPEM, srvEncPEM := prof.GetServer()

					if err := cli.ConnectToServer(context.TODO(), srvAddr, srvPEM, srvEncPEM); err != nil {
						tui.OnLog("[red]Server error: %v[-]\n", err)
					} else {
						tui.OnLog("[green]Connected to Server[-]\n")
					}
				}()
			}
		}

		// Use IsComplete() to determine if we need to show the setup form
		if !prof.IsComplete() {
			tui.showNicknameForm(startConnection)
		} else {
			startConnection()
		}
	}

	prof, err := profile.Load(profile.DefaultPath, "")

	if err == profile.ErrPasswordRequired {
		tui.showUnlockForm(func(password string) error {
			p, e := profile.Load(profile.DefaultPath, password)
			if e != nil {
				return e
			}
			tui.App.QueueUpdateDraw(func() {
				initializeApp(p)
			})
			return nil
		})
	} else if err != nil && !os.IsNotExist(err) {
		log.Fatal(err)
	} else {
		initializeApp(prof)
	}

	if err := tui.App.Run(); err != nil {
		term.Restore(int(os.Stdin.Fd()), nil)
		panic(err)
	}

	fmt.Println("Shutting down...")
	if tui.Client != nil {
		tui.Client.Shutdown()
	}
	fmt.Println("Goodbye.")
}