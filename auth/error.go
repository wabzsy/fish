package auth

import "errors"

var (
	ErrNoSuchUserName = "no such user with username '%s'"
	ErrNoSuchUserId   = "no such user with user id '%d'"
	ErrWrongPassword  = errors.New("shadow: wrong password")
)
