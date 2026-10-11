//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// Bond needs administrator rights, and Windows silently skips elevated apps
// listed under the Run registry key at sign-in. A scheduled task with
// "highest privileges" starts it elevated without a UAC prompt instead.
const taskName = "Bond"

const taskXML = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Start Bond in the system tray when you sign in.</Description></RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled><UserId>%[1]s</UserId><Delay>PT5S</Delay></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author"><UserId>%[1]s</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>4</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>%[2]s</Command><Arguments>--background</Arguments><WorkingDirectory>%[3]s</WorkingDirectory></Exec>
  </Actions>
</Task>
`

func schtasks(args ...string) (string, error) {
	cmd := exec.Command("schtasks.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// autoStartEnabled reports whether the logon task exists and points at this
// executable.
func autoStartEnabled() bool {
	out, err := schtasks("/Query", "/TN", taskName, "/XML")
	if err != nil {
		return false
	}
	exe, _ := os.Executable()
	return strings.Contains(strings.ToLower(out), strings.ToLower(html.EscapeString(exe)))
}

func setAutoStart(on bool) error {
	if !on {
		if _, err := schtasks("/Query", "/TN", taskName); err != nil {
			return nil // nothing to remove
		}
		if out, err := schtasks("/Delete", "/TN", taskName, "/F"); err != nil {
			return fmt.Errorf("remove startup task: %s", out)
		}
		return nil
	}
	tok := windows.GetCurrentProcessToken()
	user, err := tok.GetTokenUser()
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	x := fmt.Sprintf(taskXML, user.User.Sid.String(), html.EscapeString(exe), html.EscapeString(filepath.Dir(exe)))

	// schtasks wants the XML as UTF-16 with a byte order mark.
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xFE})
	binary.Write(&buf, binary.LittleEndian, utf16.Encode([]rune(x)))
	f, err := os.CreateTemp("", "bond-task-*.xml")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	f.Write(buf.Bytes())
	f.Close()
	if out, err := schtasks("/Create", "/TN", taskName, "/XML", f.Name(), "/F"); err != nil {
		return fmt.Errorf("create startup task: %s", out)
	}
	return nil
}
