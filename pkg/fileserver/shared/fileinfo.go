package shared

import (
	"errors"
	"fileserver/pkg/exterror"
	"log/slog"
	"os"
	"strings"
	"time"
)

type FileType int

const (
	File = 1 << iota
	Folder
)

const TimeFormat = time.RFC3339

type Item struct {
	Key  string    `json:"key"`
	File *FileInfo `json:"file,omitempty"`
}

type FileInfo struct {
	Path string `json:"path,omitempty"`
	// original name
	Name string `json:"name"`
	// for admin purposes
	Comment string `json:"comment,omitempty"`
	// need password on access
	Hash string `json:"hash,omitempty"`
	// time.RFC3339
	UploadDateTime string `json:"uploaded,omitempty"`
	// time.RFC3339 data wygasania
	ExpirationTime string `json:"expiration,omitempty"`
	ContentType    string `json:"content_type,omitempty"`
	Size           string `json:"size"`
	Value          string `json:"v,omitempty"`
}

func (self *FileInfo) IsExpired(when time.Time) bool {
	if len(self.ExpirationTime) == 0 {
		return false
	} else {
		if v, err := time.Parse(TimeFormat, self.ExpirationTime); err != nil {
			slog.Warn("ExpirationTime wrong format %v: %v", self.ExpirationTime, err)
			return false
		} else {
			return v.Before(when)
		}
	}
}

func (self *FileInfo) Id() (string, *exterror.Error) {
	if len(self.Path) == 0 {
		return "", exterror.NewInternalServerWrap(ErrItemIsNotRegularFile)
	}
	idx := strings.LastIndex(self.Path, string(os.PathSeparator))

	if idx > 0 {
		if idx+1 >= len(self.Path) {
			return "", exterror.NewInternalServerWrap(errors.New("it is not regular file or don't have id"))
		}
	} else {
		return "", exterror.NewInternalServerWrap(errors.New("it is not regular file or don't have set path"))
	}
	//}
	//	lastId = value
	//if value > lastId {
	return self.Path[idx+1:], nil
}

var ErrItemIsNotRegularFile = errors.New("item is not a regular file")
var ErrKeyNameSyntaxError = errors.New("key is empty or contains illegal characters")
var ErrCantReplaceFile = errors.New("can't replace file with folder and vice versa")
var ErrCantRemoveDirectoryAsFile = errors.New("can't remove directory, use removeall")
