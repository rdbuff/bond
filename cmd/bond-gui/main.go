//go:build windows

// bond-gui is the windowed Bond client: an on/off switch for the bonded tunnel
// with live per-path throughput. The embedded manifest makes Windows ask for
// administrator rights, which creating the tunnel adapter needs.
package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"unsafe"

	"fyne.io/systray"
	"github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"

	"github.com/rdbuff/bond/internal/adblock"
	"github.com/rdbuff/bond/internal/client"
)

//go:embed index.html
var indexHTML string

const (
	winW, winH = 400, 720
	iconID     = 1 // RT_GROUP_ICON #1 in winres.json
)

type app struct {
	cfg    client.Config
	filter *adblock.Filter

	mu    sync.Mutex
	fs    fileSettings // what bond.json holds
	c     *client.Client
	state string // off, starting, on, stopping
	err   string

	listLoading bool
	listErr     string
	abErr       string

	win *window
	wv  webview2.WebView

	abMu     sync.Mutex // serializes ad blocker state changes
	abGen    int
	resolver *adblock.Server
}

type uiStatus struct {
	State      string         `json:"state"` // off, starting, connecting, connected, stopping
	Error      string         `json:"error"`
	Tunnel     *client.Status `json:"tunnel,omitempty"`
	AdBlock    uiAdBlock      `json:"adblock"`
	KillSwitch bool           `json:"killSwitch"`
	NeedsSetup bool           `json:"needsSetup"` // no relay server or key yet
}

func (a *app) getStatus() uiStatus {
	a.mu.Lock()
	c, st := a.c, uiStatus{State: a.state, Error: a.err, KillSwitch: a.cfg.KillSwitch}
	_, keyErr := os.Stat(keyPath())
	st.NeedsSetup = a.cfg.Server == "" || keyErr != nil
	a.mu.Unlock()
	if st.State == "on" && c != nil {
		s := c.Status()
		st.State, st.Tunnel = s.State, &s
	}
	st.AdBlock = a.adBlockStatus()
	return st
}

// setEnabled starts or stops the tunnel in the background; the UI follows
// progress through getStatus.
func (a *app) setEnabled(on bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case on && a.state == "off":
		a.state, a.err = "starting", ""
		go a.start(a.cfg)
	case !on && a.state == "on":
		a.state = "stopping"
		c := a.c
		go func() {
			c.Stop()
			a.mu.Lock()
			a.c, a.state = nil, "off"
			a.mu.Unlock()
		}()
	}
}

// start brings the tunnel up; the caller has set state to "starting".
func (a *app) start(cfg client.Config) {
	c, err := client.Start(cfg)
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		a.state, a.err = "off", err.Error()
		return
	}
	a.c, a.state = c, "on"
}

// restart reconnects with the current settings if the tunnel is on.
func (a *app) restart() {
	a.mu.Lock()
	if a.state != "on" {
		a.mu.Unlock()
		return
	}
	c := a.c
	a.state = "stopping"
	a.mu.Unlock()
	go func() {
		c.Stop()
		a.mu.Lock()
		a.c, a.state, a.err = nil, "starting", ""
		cfg := a.cfg
		a.mu.Unlock()
		a.start(cfg)
	}()
}

// shutdown stops the tunnel when the window closes, waiting for a start in
// progress to finish first.
func (a *app) shutdown() {
	for {
		a.mu.Lock()
		state, c := a.state, a.c
		a.mu.Unlock()
		switch state {
		case "on":
			c.Stop()
			return
		case "off":
			return
		}
		windows.SleepEx(50, false)
	}
}

// loadConfig starts from the defaults and applies bond.json from the config
// folder, if present. Without saved connections it bonds every interface
// that currently has an internet gateway.
func loadConfig() (client.Config, fileSettings, error) {
	cfg := client.DefaultConfig()
	if gw := client.GatewayInterfaces(); len(gw) > 0 {
		cfg.Paths = gw
	}
	var fs fileSettings
	b, err := os.ReadFile(settingsPath())
	if os.IsNotExist(err) {
		return cfg, fs, nil
	} else if err != nil {
		return cfg, fs, err
	}
	if err := json.Unmarshal(b, &fs); err != nil {
		return cfg, fs, fmt.Errorf("bond.json: %w", err)
	}
	fs.apply(&cfg)
	return cfg, fs, nil
}

func messageBox(text string) {
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString("Bond")
	windows.MessageBox(0, t, c, windows.MB_OK|windows.MB_ICONERROR)
}

var getDpiForWindow = windows.NewLazySystemDLL("user32.dll").NewProc("GetDpiForWindow")

func main() {
	// Helper modes used by the installer and uninstaller; no window.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--set-autostart":
			if err := setAutoStart(len(os.Args) > 2 && os.Args[2] == "on"); err != nil {
				os.Exit(1)
			}
			return
		case "--cleanup":
			setAutoStart(false)
			setDNSPolicy(false)
			flushDNSCache()
			return
		}
	}
	// One window at a time; the tunnel itself is also guarded in client.Start.
	name, _ := windows.UTF16PtrFromString(`Local\BondGUI`)
	if _, err := windows.CreateMutex(nil, false, name); err == windows.ERROR_ALREADY_EXISTS {
		if !showExisting() {
			messageBox("Bond is already running.")
		}
		return
	}
	// --background: started at sign-in; stay in the tray.
	background := slices.Contains(os.Args[1:], "--background")
	cfg, fs, err := loadConfig()
	if err != nil {
		messageBox(err.Error())
		return
	}
	filter := adblock.NewFilter()
	filter.SetAllow(fs.AdBlockAllow)
	filter.SetEnabled(fs.AdBlock)
	a := &app{cfg: cfg, fs: fs, filter: filter, state: "off"}
	a.abApply() // also removes a DNS rule left behind by a crash
	go a.refreshLists()

	dataDir := filepath.Join(os.Getenv("LOCALAPPDATA"), "Bond", "WebView2")
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		DataPath:  dataDir,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title: "Bond", Width: winW, Height: winH, IconId: iconID, Center: true,
		},
	})
	if w == nil {
		messageBox("Could not start the window. Is the Microsoft Edge WebView2 Runtime installed?")
		return
	}
	scale := 1.0
	if getDpiForWindow.Find() == nil {
		if dpi, _, _ := getDpiForWindow.Call(uintptr(unsafe.Pointer(w.Window()))); dpi > 0 {
			scale = float64(dpi) / 96
		}
	}
	w.SetSize(int(winW*scale), int(winH*scale), webview2.HintFixed)
	w.Bind("getStatus", a.getStatus)
	w.Bind("setEnabled", a.setEnabled)
	w.Bind("getSettings", a.getSettings)
	w.Bind("saveSettings", a.saveSettings)
	w.Bind("setAdBlock", a.setAdBlock)
	w.Bind("windowAction", a.windowAction)
	w.SetHtml(indexHTML)

	win := &window{hwnd: uintptr(w.Window()), onClose: a.handleClose, onMinimize: a.handleMinimize}
	a.win, a.wv = win, w
	win.subclass()
	if background {
		win.hide()
	}
	a.runTray(win)
	if fs.AutoConnect {
		a.setEnabled(true)
	}

	w.Run()
	a.shutdown()
	a.abShutdown()
	systray.Quit()
}
