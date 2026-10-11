//go:build windows

package main

import "fmt"

// What the close (X) and minimize buttons do. "ask" shows a dialog in the
// window; the other values are remembered answers.
const (
	actAsk     = "ask"
	actTray    = "tray"
	actQuit    = "quit"
	actTaskbar = "taskbar"
)

var (
	closeActions    = []string{actAsk, actTray, actQuit}
	minimizeActions = []string{actAsk, actTray, actTaskbar}
)

func validAction(v string, allowed []string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

func orAsk(v string) string {
	if v == "" {
		return actAsk
	}
	return v
}

// handleClose runs on the UI thread when the X is clicked; it returns true
// when it took care of the click, false to let the window close (quit).
func (a *app) handleClose() bool {
	a.mu.Lock()
	mode := orAsk(a.fs.OnClose)
	a.mu.Unlock()
	switch mode {
	case actQuit:
		return false
	case actTray:
		a.win.hide()
	default:
		a.win.show() // e.g. closed from the taskbar while minimized
		a.ask("close")
	}
	return true
}

// handleMinimize returns true when it took care of the click, false to let
// Windows minimize to the taskbar as usual.
func (a *app) handleMinimize() bool {
	a.mu.Lock()
	mode := orAsk(a.fs.OnMinimize)
	a.mu.Unlock()
	switch mode {
	case actTaskbar:
		return false
	case actTray:
		a.win.hide()
	default:
		a.ask("minimize")
	}
	return true
}

func (a *app) ask(kind string) {
	a.wv.Dispatch(func() { a.wv.Eval(fmt.Sprintf("askWindow(%q)", kind)) })
}

// windowAction carries out the user's answer to a close/minimize dialog and,
// if asked to, remembers it. kind is "close" or "minimize"; action is one of
// tray, quit, taskbar or cancel.
func (a *app) windowAction(kind, action string, remember bool) string {
	if action == "cancel" {
		return ""
	}
	allowed := closeActions
	if kind == "minimize" {
		allowed = minimizeActions
	}
	if !validAction(action, allowed) || action == actAsk {
		return "unknown action " + action
	}
	var err error
	if remember {
		a.mu.Lock()
		if kind == "minimize" {
			a.fs.OnMinimize = action
		} else {
			a.fs.OnClose = action
		}
		err = a.fs.save()
		a.mu.Unlock()
	}
	switch action {
	case actQuit:
		a.win.quit()
	case actTray:
		a.win.hide()
	case actTaskbar:
		a.win.minimize()
	}
	if err != nil {
		return "Couldn't save your choice: " + err.Error()
	}
	return ""
}
