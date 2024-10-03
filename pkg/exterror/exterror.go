package exterror

import (
	"errors"
	"fmt"
)

// you can register custom error codes
// below basic codes
var ErrNotFoundCode = 404
var ErrForbiddenCode = 403
var ErrUnauthorizedCode = 401
var ErrInternalServerCode = 501
var ErrUnprocessableEntity = 422
var DefaultMessageIfEmpty = ""

func NewNotFound() *Error {
	return New(ErrNotFoundCode, nil, "")
}
func NewNotFoundWrap(err error) *Error {
	return New(ErrNotFoundCode, err, "")
}

func NewForbidden() *Error {
	return New(ErrForbiddenCode, nil, "")
}

func NewForbiddenWrap(err error) *Error {
	return New(ErrForbiddenCode, err, "")
}
func NewUnauthorized() *Error {
	return New(ErrUnauthorizedCode, nil, "")
}
func NewUnauthorizedWrap(err error) *Error {
	return New(ErrUnauthorizedCode, err, "")
}

func NewInternalServer() *Error {
	return New(ErrInternalServerCode, nil, "")
}
func NewInternalServerWrap(err error) *Error {
	return New(ErrInternalServerCode, err, "")
}

func NewUnprocessableEntity() *Error {
	return New(ErrUnprocessableEntity, nil, "")
}
func NewUnprocessableEntityWrap(err error) *Error {
	return New(ErrUnprocessableEntity, err, "")
}

func New(code int, casue error, comment string) *Error {
	return &Error{
		code, comment, casue,
	}
}

type Error struct {
	code int
	// public safe message about case of error
	comment string

	cause error
}

func (self *Error) SetCode(code int) *Error {
	self.code = code
	return self
}
func (self *Error) SetCommentf(format string, args ...interface{}) *Error {
	self.comment = fmt.Sprintf(format, args...)
	return self
}

func (self *Error) SetComment(comment string) *Error {
	self.comment = comment
	return self
}

func (self *Error) String() string {
	return fmt.Sprintf("code: %v, comment: %s cause: %v", self.code, self.Error(), self.Cause())
}

func (self *Error) Error() string {
	if len(self.comment) > 0 {
		return self.comment
	}
	return GetCode(self.code, DefaultMessageIfEmpty)
}

func (self *Error) Code() int {
	return self.code
}

func (self *Error) Cause() error {
	return self.cause
}

type CauseHolder interface {
	Cause() error
}

// Cause returns to the parent and returns the root cause of the error
// implements the "causer" interface.
func Cause(err error) error {
	if r, ok := err.(CauseHolder); ok && r.Cause() != nil {
		return Cause(r.Cause())
	}
	return err
}

// The UnWrap function takes an error and return unwraped error.
func UnWrap(err error) error {
	if r, ok := err.(CauseHolder); ok && r != nil {
		return r.Cause()
	}
	return err
}

var pErr = &Error{}

func Is(err error) bool {
	return errors.As(err, &pErr)
}

var codesMapOfString = map[int]string{}

func SetCode(code int, value string) {
	codesMapOfString[code] = value
}

func GetCode(code int, dfault string) string {
	if v, ok := codesMapOfString[code]; ok {
		return v
	}
	return dfault
}

func init() {
	SetCode(ErrNotFoundCode, "not found")
	SetCode(ErrForbiddenCode, "forbidden")
	SetCode(ErrUnauthorizedCode, "unauthorized")
	SetCode(ErrInternalServerCode, "internal server error")
	SetCode(ErrUnprocessableEntity, "unprocessable entity")
}
