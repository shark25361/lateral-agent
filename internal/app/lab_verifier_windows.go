//go:build windows

package app

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

func destinationProcessIdentity() (string, bool, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", false, err
	}
	account, domain, _, err := user.User.Sid.LookupAccount("")
	if err != nil {
		return "", false, err
	}
	if account == "" {
		return "", false, fmt.Errorf("Windows token has no account name")
	}
	if strings.TrimSpace(domain) != "" {
		account = domain + `\` + account
	}
	return account, token.IsElevated(), nil
}
