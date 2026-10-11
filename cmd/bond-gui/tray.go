//go:build windows

package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"

	"fyne.io/systray"
	"golang.org/x/sys/windows"
)

//go:embed winres/icon.png
var iconPNG []byte

//go:embed winres/icon16.png
var icon16PNG []byte

var (
	user32               = windows.NewLazySystemDLL("user32.dll")
	procShowWindow       = user32.NewProc("ShowWindow")
	procSetForeground    = user32.NewProc("SetForegroundWindow")
	procIsIconic         = user32.NewProc("IsIconic")
	procIsWindowVisible  = user32.NewProc("IsWindowVisible")
	procSetWindowLongPtr = user32.NewProc("SetWindowLongPtrW")
	procCallWindowProc   = user32.NewProc("CallWindowProcW")
	procPostMessage      = user32.NewProc("PostMessageW")
	procFindWindow       = user32.NewProc("FindWindowW")
)

const (
	swHide     = 0
	swShow     = 5
	swRestore  = 9
	swMinimize = 6

	wmClose      = 0x0010
	wmSysCommand = 0x0112
	scMinimize   = 0xF020

	gwlpWndProc = ^uintptr(3) // -4
)

// window controls the main window's visibility. The close and minimize
// buttons are routed through onClose/onMinimize, which return true when they
// have handled the click (hidden the window or asked the user).
type window struct {
	hwnd       uintptr
	origProc   uintptr
	quitting   atomic.Bool
	onClose    func() bool
	onMinimize func() bool
}

func (w *window) subclass() {
	cb := windows.NewCallback(func(hwnd, msg, wp, lp uintptr) uintptr {
		switch {
		case msg == wmClose && !w.quitting.Load() && w.onClose():
			return 0
		case msg == wmSysCommand && wp&0xFFF0 == scMinimize && w.onMinimize():
			return 0
		}
		r, _, _ := procCallWindowProc.Call(w.origProc, hwnd, msg, wp, lp)
		return r
	})
	w.origProc, _, _ = procSetWindowLongPtr.Call(w.hwnd, gwlpWndProc, cb)
}

func (w *window) hide() { procShowWindow.Call(w.hwnd, swHide) }

// minimize sends the window to the taskbar (ShowWindow does not go through
// SC_MINIMIZE, so this does not ask again).
func (w *window) minimize() { procShowWindow.Call(w.hwnd, swMinimize) }

func (w *window) show() {
	if iconic, _, _ := procIsIconic.Call(w.hwnd); iconic != 0 {
		procShowWindow.Call(w.hwnd, swRestore)
	} else {
		procShowWindow.Call(w.hwnd, swShow)
	}
	procSetForeground.Call(w.hwnd)
}

func (w *window) visible() bool {
	v, _, _ := procIsWindowVisible.Call(w.hwnd)
	return v != 0
}

// quit closes the window for real, ending the app.
func (w *window) quit() {
	w.quitting.Store(true)
	procPostMessage.Call(w.hwnd, wmClose, 0, 0)
}

// showExisting brings an already running instance's window to the front.
func showExisting() bool {
	cls, _ := windows.UTF16PtrFromString("webview")
	title, _ := windows.UTF16PtrFromString("Bond")
	hwnd, _, _ := procFindWindow.Call(uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(title)))
	if hwnd == 0 {
		return false
	}
	(&window{hwnd: hwnd}).show()
	return true
}

// runTray shows the notification-area icon on its own OS thread (Windows
// delivers a window's messages to the thread that created it).
func (a *app) runTray(w *window) {
	onIcon, offIcon := makeICO(false), makeICO(true)
	go func() {
		runtime.LockOSThread()
		systray.Run(func() {
			systray.SetIcon(offIcon)
			systray.SetTooltip("Bond")
			systray.SetOnTapped(w.show)
			open := systray.AddMenuItem("Open Bond", "Show the Bond window")
			systray.AddSeparator()
			bonding := systray.AddMenuItemCheckbox("Bonding", "Combine WiFi and Ethernet", false)
			adblock := systray.AddMenuItemCheckbox("Ad blocker", "Block ads and trackers", false)
			systray.AddSeparator()
			quit := systray.AddMenuItem("Quit Bond", "Turn everything off and exit")

			go func() {
				lastOn := false
				systray.SetIcon(offIcon)
				for {
					st := a.getStatus()
					on := st.State != "off" && st.State != "stopping"
					setChecked(bonding, on)
					setChecked(adblock, st.AdBlock.Enabled)
					if on != lastOn {
						if on {
							systray.SetIcon(onIcon)
						} else {
							systray.SetIcon(offIcon)
						}
						lastOn = on
					}
					systray.SetTooltip(trayTooltip(st))
					select {
					case <-open.ClickedCh:
						w.show()
					case <-bonding.ClickedCh:
						a.setEnabled(!on)
					case <-adblock.ClickedCh:
						a.setAdBlock(!st.AdBlock.Enabled)
					case <-quit.ClickedCh:
						w.quit()
						return
					case <-time.After(time.Second):
					}
				}
			}()
		}, nil)
	}()
}

func setChecked(item *systray.MenuItem, on bool) {
	if item.Checked() != on {
		if on {
			item.Check()
		} else {
			item.Uncheck()
		}
	}
}

func trayTooltip(st uiStatus) string {
	s := "Bond: off"
	switch st.State {
	case "starting", "connecting":
		s = "Bond: connecting…"
	case "stopping":
		s = "Bond: turning off…"
	case "connected":
		s = "Bond: connected"
		if t := st.Tunnel; t != nil {
			s += fmt.Sprintf("\nDown %.0f / Up %.0f Mbps", t.RxMbps, t.TxMbps)
		}
	}
	if st.AdBlock.Enabled {
		s += fmt.Sprintf("\nAd blocker: %d blocked", st.AdBlock.Blocked)
	}
	return s
}

// makeICO builds a .ico holding the 16px and 256px PNG icons, optionally
// greyed out for the "off" state.
func makeICO(grey bool) []byte {
	imgs := [][]byte{icon16PNG, iconPNG}
	if grey {
		for i, b := range imgs {
			imgs[i] = greyPNG(b)
		}
	}
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, [3]uint16{0, 1, uint16(len(imgs))})
	offset := 6 + 16*len(imgs)
	for _, b := range imgs {
		cfg, _ := png.DecodeConfig(bytes.NewReader(b))
		dim := func(n int) uint8 {
			if n >= 256 {
				return 0
			}
			return uint8(n)
		}
		buf.Write([]byte{dim(cfg.Width), dim(cfg.Height), 0, 0})
		binary.Write(&buf, binary.LittleEndian, [2]uint16{1, 32})
		binary.Write(&buf, binary.LittleEndian, [2]uint32{uint32(len(b)), uint32(offset)})
		offset += len(b)
	}
	for _, b := range imgs {
		buf.Write(b)
	}
	return buf.Bytes()
}

func greyPNG(b []byte) []byte {
	src, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		return b
	}
	r := src.Bounds()
	dst := image.NewNRGBA(r)
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			c := color.NRGBAModel.Convert(src.At(x, y)).(color.NRGBA)
			l := uint8((299*uint32(c.R) + 587*uint32(c.G) + 114*uint32(c.B)) / 1000)
			l = uint8(uint32(l)*3/4 + 32)
			dst.SetNRGBA(x, y, color.NRGBA{l, l, l, c.A})
		}
	}
	var out bytes.Buffer
	png.Encode(&out, dst)
	return out.Bytes()
}
