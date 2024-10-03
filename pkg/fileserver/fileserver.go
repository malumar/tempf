package fileserver

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fileserver/pkg/exterror"
	"fileserver/pkg/fileserver/shared"
	"fileserver/pkg/genrand"
	"fileserver/pkg/pull"
	"fileserver/pkg/strutil"
	"fmt"
	"github.com/tidwall/buntdb"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const storagePath = "storage"
const configFilename = "fileserver.db"
const apiKeyLength = 32
const pathSeparator = "#"
const filesPfx = "files#"
const rootPfx = "root#"

type Config struct {
	Addr            string   `json:"addr"`
	SecureAddr      string   `json:"secure_addr"`
	Ssl             bool     `json:"ssl"`
	Domains         []string `json:"domains"`
	Path            string   `json:path`
	AllowList       []string
	MaxUploadSize   int64
	MaxMemoryStore  int64
	DisabledHandler map[string]bool
}

type Options struct {
	Comment      string
	Hash         string
	ExpireAfter  string
	OriginalName string
	ContentType  string
}

func DefaultConfig() *Config {
	return &Config{
		Addr:       ":18080",
		SecureAddr: ":https",
		Ssl:        false,
		Path:       "",
		// maximum upload of 10 M0 files
		MaxUploadSize:   10 << 20,
		DisabledHandler: make(map[string]bool),
	}
}

func New(cfg *Config) (*FileServer, *exterror.Error) {

	if !filepath.IsAbs(cfg.Path) {
		return nil, exterror.NewInternalServerWrap(errors.New("storage path must be absolute"))
	}
	// disallow root directory
	p := strings.TrimSpace(strings.ReplaceAll(cfg.Path, " ", ""))
	if len(p) == 0 || p == "/" || strings.Index(p, `//`) > 0 || strings.Index(p, `\\`) > 0 {
		return nil, exterror.NewInternalServerWrap(errors.New("invalid config path"))
	}

	sp := filepath.Join(cfg.Path, storagePath)

	if _, err := os.Stat(sp); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(sp, os.ModePerm)
		if err != nil {
			slog.Error("FileServer.New: %v", err)
		}
	}

	db, err := buntdb.Open(filepath.Join(cfg.Path, configFilename))
	if err != nil {
		return nil, exterror.NewInternalServerWrap(err)
	}

	fs := &FileServer{
		storagePath: sp,
		config:      cfg,
		db:          db,
	}

	//fs.db = db
	//fs.config = cfg

	// check apikey, if not exist generate one
	if ak, err := fs.getConfigKey("apikey"); err != nil {
		if err == buntdb.ErrNotFound {
			slog.Info("api key is not set")
			if newApiKey, err := fs.ResetApiKey(); err != nil {
				slog.Warn("can't setup api key, do it manually", "reason", err)
			} else {
				slog.Info("created api key is", "key", newApiKey)
			}

		} else {
			return nil, err
		}
	} else {
		fs.apiKey = ak
	}

	if ak, err := fs.getConfigKey("apikey"); err == nil {
		if err == buntdb.ErrNotFound {
			slog.Info(" api key is not settted")
			if newApiKey, err := fs.ResetApiKey(); err != nil {

				slog.Error("can't setup api key, do it manually", "reason", err)
			} else {
				slog.Info("created api key is", slog.Any("key", newApiKey))
			}

		}
	} else {
		fs.apiKey = ak
	}

	var lastId string
	if err := fs.db.View(func(tx *buntdb.Tx) error {
		return tx.AscendKeys(filesPfx+"*", func(key, value string) bool {
			// skip folders
			if len(value) > 0 {
				if fi, err := ToFileInfo(value); err != nil {
					slog.Warn("unmarshal file info %v: %v", key, err)
				} else {
					if id, err := fi.Id(); err != nil {
						slog.Warn("get file info %v: %v", key, err)
					} else {
						if id > lastId {
							lastId = id
						}
					}
				}
			}
			return true
		})
	}); err != nil {
		if errors.Is(err, buntdb.ErrNotFound) {
			return nil, exterror.NewNotFoundWrap(errors.New("can't find lastId"))
		}
		return nil, exterror.NewInternalServerWrap(err)
	}

	if len(lastId) > 0 {
		value, err := strconv.ParseUint(lastId, 16, 64)
		if err != nil {
			return nil, exterror.NewInternalServerWrap(fmt.Errorf("convert lastId to int: %w", err))
		}
		fs.lastId.Store(value)
	}

	return fs, nil
}

type FileServer struct {
	db          *buntdb.DB
	config      *Config
	storagePath string
	lastId      atomic.Uint64

	httpSrv *http.Server

	lock   sync.RWMutex
	apiKey string
}

// GetFileReaderWithoutAuthorization don't require hash for validation
func (self *FileServer) GetFileReaderWithoutAuthorization(fi *shared.FileInfo) (io.ReadSeeker, *exterror.Error) {
	if fi == nil {
		return nil, exterror.NewNotFoundWrap(errors.New("file info is empty"))
	}

	if _, err := fi.Id(); err != nil {
		return nil, err
	}
	return self.getFileReader(fi)
}
func (self *FileServer) GetFileReaderIfAuthorized(fi *shared.FileInfo, hash string) (io.ReadSeeker, *exterror.Error) {

	if fi == nil {
		return nil, exterror.NewNotFoundWrap(errors.New("file info is empty"))
	}

	if _, err := fi.Id(); err != nil {
		return nil, err
	}

	if len(fi.Hash) > 0 {
		//hash := client.ParamValue("hash")
		//if val := client.HeaderValue("X-Hash"); len(val) > 0 {
		//	hash = val
		//}

		if len(hash) == 0 {
			return nil, exterror.NewUnauthorizedWrap(errors.New("hash is empty"))
		} else {
			if fi.Hash != hash {
				return nil, exterror.NewForbiddenWrap(errors.New("hash does not match"))
			}
		}
	} else {
		if len(hash) > 0 {
			if len(fi.Hash) == 0 {
				return nil, exterror.NewForbiddenWrap(errors.New("item does not have hash set"))
			}
		}
	}

	//client.Header().Set("Content-Length", fi.Size)
	//client.Header().Set("Content-Type", fi.ContentType)
	//http.ServeContent(client, client.Request(), fi.Name, stat.ModTime(), f)
	return self.getFileReader(fi)
}

func (self *FileServer) getFileReader(fi *shared.FileInfo) (io.ReadSeeker, *exterror.Error) {
	// file content stored in FileInfo?
	if len(fi.Value) >= 1 {
		// any content or empty?
		if fi.Value[0] == '1' {
			return bytes.NewReader([]byte(fi.Value[1:])), nil
			return strings.NewReader(fi.Value[1:]), nil
		}
		return strings.NewReader(""), nil
	}

	absolutePath := filepath.Join(self.StoragePath(), fi.Path)

	f, err := os.Open(absolutePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, exterror.NewNotFoundWrap(err)
		}
		return nil, exterror.NewInternalServerWrap(err)
	}

	stat, _ := f.Stat()

	if stat.IsDir() {
		f.Close()
		return nil, exterror.NewNotFoundWrap(errors.New("item is directory"))
	}

	return f, nil
}

func (self *FileServer) StoragePath() string {
	return self.storagePath
}

func (self *FileServer) Config() *Config {
	return self.config
}

func (self *FileServer) GetApiKey() string {
	self.lock.RLock()
	defer self.lock.RUnlock()
	return self.apiKey
}

func (self *FileServer) newId() string {
	return fmt.Sprintf("%016x", self.lastId.Add(1))
}

func (self *FileServer) ResetApiKey() (string, *exterror.Error) {
	dat, err := genrand.Bytes(apiKeyLength)
	if err != nil {
		return "", exterror.NewInternalServerWrap(err)
	}
	newKey := base64.StdEncoding.EncodeToString(dat)
	if err := self.UpdateApiKey(newKey); err != nil {
		return "", err
	}

	return newKey, nil
}

func (self *FileServer) IsDirectoryExists(name string) (bool, *exterror.Error) {

	return self.isExists(name, true)

}

func (self *FileServer) IsFileExists(name string) (bool, *exterror.Error) {

	return self.isExists(name, false)

}

func (self *FileServer) GetFileInfo(key string, skipExpired bool) (*shared.FileInfo, *exterror.Error) {

	if err := IsValidFilename(key, false); err != nil {

		return nil, err
	}

	preparedKey := filesPfx + key

	var ret string
	if err := self.db.View(func(tx *buntdb.Tx) error {
		if val, err := tx.Get(preparedKey); err != nil {
			return err
		} else {
			if len(val) == 0 {
				return buntdb.ErrNotFound
			}
			ret = val

		}
		return nil
	}); err != nil {
		if err == buntdb.ErrNotFound {
			return nil, exterror.NewNotFound()
		}
		return nil, exterror.NewInternalServerWrap(err)
	}

	if len(ret) == 0 {
		return nil, exterror.NewNotFoundWrap(errors.New("key value is empty"))
	}

	fi, err := ToFileInfo(ret)
	if err != nil {
		return nil, err
	}

	if skipExpired && fi.IsExpired(time.Now()) {
		go func() {
			if err := self.Remove(key); err != nil {
				slog.Error("GetFileInfo", "reason", err)
			} else {
				slog.Info(" %v: %v expired and deleted", key, fi.Path)
			}
		}()

		return nil, exterror.NewNotFoundWrap(errors.New("key is expired"))
	}

	return fi, nil

	//return filepath.Join(t.storagePath, ret), nil
}

func (self *FileServer) isExists(name string, checkIsDir bool) (bool, *exterror.Error) {

	if err := IsValidKey(name, false, checkIsDir); err != nil {
		return false, err
	}

	key := filesPfx + name
	if err := self.db.View(func(tx *buntdb.Tx) error {
		// empty value is directory
		if val, err := tx.Get(key); err != nil {
			return err
		} else {
			if len(val) == 0 {
				if checkIsDir {
					return nil
				}
				return buntdb.ErrNotFound
			} else {
				if checkIsDir {
					return buntdb.ErrNotFound
				}

			}
		}
		return nil
	}); err != nil {
		if err == buntdb.ErrNotFound {
			return false, nil
		} else {
			return false, exterror.NewInternalServerWrap(err)
		}
	}

	return true, nil

}

func (self *FileServer) MkDir(name string) *exterror.Error {
	if err := ValidatePath(name); err != nil {
		return err
	}
	key := filesPfx + name
	if err := self.db.Update(func(tx *buntdb.Tx) error {
		// empty value is directory
		if val, replaced, err := tx.Set(key, "", nil); err != nil {
			return err
		} else {
			if replaced {
				if len(val) > 0 {
					return exterror.NewUnprocessableEntityWrap(errors.New("can't create directory, already exists"))
				}
			}
		}
		return nil

	}); err != nil {
		if errors.Is(err, buntdb.ErrNotFound) {
			return exterror.NewNotFound()
		}
		if exterror.Is(err) {
			return err.(*exterror.Error)
		}
		return exterror.NewInternalServerWrap(err)
	}
	slog.Info("mkdir", "folder", name)
	return nil
}

func (self *FileServer) Remove(key string) *exterror.Error {
	if err := IsValidFilename(key, false); err != nil {
		return err
	}
	preparedKey := filesPfx + key
	var dat string
	if err := self.db.Update(func(tx *buntdb.Tx) error {

		if val, err := tx.Delete(preparedKey); err != nil {
			return err
		} else {
			// empty value is directory
			if len(val) == 0 {
				return shared.ErrCantRemoveDirectoryAsFile
			}
			dat = val
		}
		return nil
	}); err != nil {
		if errors.Is(err, buntdb.ErrNotFound) {
			return exterror.NewNotFound()
		}

		if errors.Is(err, shared.ErrCantRemoveDirectoryAsFile) {
			return exterror.NewUnprocessableEntityWrap(shared.ErrCantRemoveDirectoryAsFile).
				SetComment(shared.ErrCantRemoveDirectoryAsFile.Error())
		}

		return exterror.NewInternalServerWrap(err)

	}
	if len(dat) > 0 {
		if fi, err := ToFileInfo(dat); err != nil {
			return err
		} else {
			return self.removeFileFromStorage(fi)
		}

	}

	return nil
}

// List returns the specified item matches the pattern (if wildcard = true). This is a very
// simple pattern matcher where '*' matches on any number characters and '?'
// matches on any one character.
// handler called when finded file or directory (fileInfo is nil)
// return true, nil if you want next results
func (self *FileServer) List(isAuthorized bool, pth string, wildcard bool, include shared.FileType, limit int,
	handler func(key string, fileInfo *shared.FileInfo) (bool, *exterror.Error)) *exterror.Error {

	if wildcard {
		if include&shared.File != 0 && include&shared.Folder != 0 {
			if err := ValidateWildcardPath(pth); err != nil {
				return err
			}
		} else {
			if include&shared.File != 0 {
				if err := IsValidKey(pth, wildcard, false); err != nil {
					return err
				}
			} else if include&shared.Folder != 0 {
				if err := IsValidKey(pth, wildcard, true); err != nil {
					return err
				}
			} else {
				return exterror.NewUnprocessableEntity().SetComment("include is required")
			}
		}
	}
	preparedKey := filesPfx + pth

	if !wildcard {
		preparedKey += "*"
	}

	if !isAuthorized {
		var found bool
		for _, item := range self.config.AllowList {
			if strutil.Match(item, pth) {
				found = true
				slog.Debug("matched to allowlist", "pattern", item, "value", pth)
				break
			} else {
				slog.Debug("not match allowlist", "pattern", item, "value", pth)
			}
		}
		if !found {
			return exterror.NewUnauthorizedWrap(errors.New("allowlist not match to query")).SetComment("please login")
		}
	}

	items := sliceOfString.Get()
	defer sliceOfString.Put(items)

	if err := self.db.Update(func(tx *buntdb.Tx) error {

		tx.AscendKeys(preparedKey, func(key, value string) bool {
			if len(value) == 0 {
				if include&shared.Folder != 0 {
					items = append(items, key+"\n")
				}
			} else {
				if include&shared.File != 0 {
					items = append(items, key+"\n"+value)
				}
			}

			return true
		})
		return nil

	}); err != nil {
		if errors.Is(err, buntdb.ErrNotFound) {
			return nil
		} else {
			return exterror.NewInternalServerWrap(err)
		}
	}

	var count int
	for _, item := range items {
		// remove private db pfx from key
		item = item[len(filesPfx):]
		for i, c := range item {
			if c == '\n' {
				key := item[:i]
				if len(item)-1 > i {
					var fi shared.FileInfo
					if err := json.Unmarshal([]byte(item[i+1:]), &fi); err != nil {
						slog.Error("List.Unmarshal", "id", key, "err", err)
						continue
					}

					if fi.IsExpired(time.Now()) {
						continue
					}

					fi.Path = ""
					fi.Value = ""

					if next, err := handler(key, &fi); err != nil {
						return err
					} else {
						if !next {
							return nil
						}
					}
				} else {
					if next, err := handler(key, nil); err != nil {
						return err
					} else {
						if !next {
							return nil
						}
					}
				}

				if limit > 0 && count >= limit {
					return nil
				}

			}
		}
	}

	return nil
}

func (self *FileServer) RemoveAll(key string, useWildcard bool) *exterror.Error {
	if useWildcard {
		if err := ValidateWildcardPath(key); err != nil {
			return err
		}
	} else {
		if err := ValidatePath(key); err != nil {
			return err
		}

	}
	preparedKey := filesPfx + key

	if !useWildcard {
		preparedKey += "*"
	}

	keys := sliceOfString.Get()
	values := sliceOfString.Get()
	defer sliceOfString.Put(keys)
	defer sliceOfString.Put(values)

	if err := self.db.Update(func(tx *buntdb.Tx) error {

		if val, err := tx.Delete(preparedKey); err != nil {
			if err != buntdb.ErrNotFound {
				return err
			}

		} else {
			if len(val) != 0 {
				return exterror.NewNotFoundWrap(shared.ErrItemIsNotRegularFile)
			}
		}

		if err := tx.AscendKeys(preparedKey, func(k, value string) bool {
			keys = append(keys, k)
			// skip if directory
			if len(value) > 0 {
				values = append(values, value)
			}
			return true
		}); err != nil {
			return err
		}

		for _, k := range keys {
			if _, err := tx.Delete(k); err != nil {
				if err != buntdb.ErrNotFound {
					return err
				}
			}
		}

		return nil

	}); err != nil {
		if err != buntdb.ErrNotFound {
			return exterror.NewNotFoundWrap(err)
		}

	}

	for _, val := range values {
		fi, err := ToFileInfo(val)
		if err != nil {
			slog.Error(" can't delete file wrong FileInfo structure", "reason", err)
		} else {
			if err := self.removeFileFromStorage(fi); err != nil {
				slog.Error(" can't delete file from storage", "reason", err)
			}
		}
	}

	return nil
}

func (self *FileServer) StoreFile(r io.Reader, size int64, key string, options ...*Options) (int64, string, *exterror.Error) {

	if err := IsValidFilename(key, false); err != nil {
		return 0, "", err
	}

	now := time.Now()
	relativeStoragePath := filepath.Join(strconv.Itoa(now.Minute()), strconv.Itoa(now.Year()), strconv.Itoa(now.YearDay()))

	tmpPth := filepath.Join(self.storagePath, relativeStoragePath)

	if _, err := os.Stat(tmpPth); os.IsNotExist(err) {
		if err := os.MkdirAll(tmpPth, 0750); err != nil {
			return 0, "", exterror.NewInternalServerWrap(err)
		}
	}
	//	generatedFilenameId := t.newId()

	fi := shared.FileInfo{
		Path:           filepath.Join(relativeStoragePath, self.newId()),
		Name:           key,
		UploadDateTime: now.Format(shared.TimeFormat),
	}

	for _, opt := range options {
		if opt != nil {
			if len(opt.ContentType) > 0 {
				fi.ContentType = opt.ContentType
			}
			if len(opt.ExpireAfter) > 0 {
				if ft, err := formatExpirationTime(opt.ExpireAfter, now); err != nil {
					return 0, "", err
				} else {
					fi.ExpirationTime = ft.Format(shared.TimeFormat)
				}
			}

		}

		if len(opt.OriginalName) > 0 {
			fi.Name = opt.OriginalName
		}

		fi.Comment = opt.Comment
		if len(opt.Hash) > 0 {
			fi.Hash = opt.Hash
		}

	}

	tempFilename := filepath.Join(self.storagePath, fi.Path)
	doRemove := true
	defer func() {
		if doRemove {
			if err := os.Remove(tempFilename); err != nil {
				slog.Error("store file failed, can't remove file", "reason", err.Error())
			}
		} else {

		}
	}()
	written, err := copyFileFromReader(r, tempFilename)
	if err != nil {
		return written, "", err
	} else {
		if written == 0 {
			return 0, "", exterror.NewInternalServerWrap(fmt.Errorf("store file failed, copied %d bytes instead of %d", written, size))
		}
	}

	fi.Size = strconv.Itoa(int(written))
	if len(fi.ContentType) == 0 ||
		strings.HasPrefix(fi.ContentType, "multipart/") ||
		fi.ContentType == "application/octet-stream" {
		if f, err := os.Open(tempFilename); err != nil {
			return 0, "", exterror.NewInternalServerWrap(fmt.Errorf("store file failed, can't open file: %v", err.Error()))
		} else {

			if ct, errx := DetectContentType(fi.Name, f); errx != nil {
				_ = f.Close()
				return 0, "", errx
			} else {
				fi.ContentType = ct
			}
			if err = f.Close(); err != nil {
				return 0, "", exterror.NewInternalServerWrap(fmt.Errorf("store file failed, can't close file: %v", err.Error()))
			}

		}

	}

	if self.config.MaxMemoryStore <= written {
		doRemove = true

		b, err := os.ReadFile(tempFilename) // just pass the file name
		if err != nil {
			return 0, "", exterror.NewInternalServerWrap(fmt.Errorf("store file failed, can't read file into memory: %v", err.Error()))
		}
		if len(b) > 0 {
			fi.Value = "1" + string(b)
		} else {
			fi.Value = "0"
		}

	}
	if err := self.PutOrReplaceFile(key, ToJson(&fi), false); err != nil {
		return 0, "", err
	}

	doRemove = false

	return written, tempFilename, nil
}

// @realFilename without storagePath
func (self *FileServer) PutOrReplaceFile(key string, value string, isDir bool) *exterror.Error {
	if err := IsValidKey(key, false, isDir); err != nil {
		return err
	}
	preparedKey := filesPfx + key

	var oldValue string
	if err := self.db.Update(func(tx *buntdb.Tx) error {

		if pv, replaced, err := tx.Set(preparedKey, value, nil); err != nil {
			return err
		} else {
			if replaced {
				if len(pv) > 0 {
					if isDir {
						return shared.ErrCantReplaceFile
					}
					oldValue = pv
				} else {
					if !isDir {
						return shared.ErrCantReplaceFile
					}
				}
			}

		}
		return nil
	}); err != nil {
		if errors.Is(err, buntdb.ErrNotFound) {
			return exterror.NewNotFound()
		}
		if errors.Is(err, shared.ErrCantReplaceFile) {
			return exterror.NewUnprocessableEntityWrap(shared.ErrCantReplaceFile).SetComment(shared.ErrCantReplaceFile.Error())
		}
		return exterror.NewInternalServerWrap(err)
	}

	if len(oldValue) > 0 {
		if fi, err := ToFileInfo(oldValue); err != nil {
			slog.Error(" can't decode file info, skip remove old file from disk", "old", oldValue, "reason", err)
		} else {
			if err := self.removeFileFromStorage(fi); err != nil {
				slog.Error(" PutOrReplaceFile can't delete file from storage", "reason", err)
			}

		}
	}
	return nil
}

// @realFilename without storagePath
//func (self *FileServer) removeFileFromStorage(realFilename string) error {
func (self *FileServer) removeFileFromStorage(fi *shared.FileInfo) *exterror.Error {
	if _, err := fi.Id(); err != nil {
		return err
	}

	// if value not empty, file stored in db
	if len(fi.Value) >= 1 {
		fi.Value = ""
		return nil
	}
	fileToRemove := filepath.Join(self.storagePath, fi.Path)
	si, err := os.Stat(fileToRemove)
	if err == nil {
		if !(si.Mode()&os.ModeType == 0) {
			slog.Error("can't delete; is not regular file", "file", fileToRemove)
			return nil
		}

		if err := os.Remove(fileToRemove); err != nil {
			slog.Error("can't remove previous file", "reason", err.Error())
		}

	} else {
		slog.Error("can't remove prev file from value  ", "file", fileToRemove, "value", fi.Path, "reason", err)
	}

	return nil

}

func (self *FileServer) UpdateApiKey(val string) *exterror.Error {
	self.lock.Lock()
	defer self.lock.Unlock()

	if len(val) == 0 {
		return exterror.NewUnprocessableEntityWrap(errors.New("new api key is empty"))
	}
	if err := self.setOrReplaceConfig("apikey", val); err == nil {
		slog.Info("api key was changed")
	} else {
		return err
	}

	self.apiKey = val
	return nil

}

func (self *FileServer) setOrReplaceConfig(key string, val string) *exterror.Error {
	k := rootPfx + key
	if err := self.db.Update(func(tx *buntdb.Tx) error {
		if _, _, err := tx.Set(k, val, nil); err != nil {
			return err
		}
		return nil
	}); err != nil {
		if err == buntdb.ErrNotFound {
			return exterror.NewNotFound()
		}
		return exterror.NewInternalServerWrap(err)
	}

	return nil
}

func (self *FileServer) getConfigKey(key string) (string, *exterror.Error) {
	k := rootPfx + key
	var retVal string
	if err := self.db.View(func(tx *buntdb.Tx) error {
		if val, err := tx.Get(k); err != nil {
			return err
		} else {
			retVal = val
		}
		return nil
	}); err != nil {
		if err == buntdb.ErrNotFound {
			return "", exterror.NewNotFound()
		}
		return "", exterror.NewInternalServerWrap(err)
	}

	return retVal, nil
}
func ValidateWildcardPath(key string) *exterror.Error {
	return IsValidKey(key, true, true)
}
func ValidatePath(key string) *exterror.Error {
	return IsValidKey(key, false, true)
}
func IsValidFilename(key string, allowMatchCharacters bool) *exterror.Error {
	return IsValidKey(key, allowMatchCharacters, false)
}

// IsValidKey validate key of specific file type, in all types white spaces are prohibited
// directory: cant't begin with slash, and must end with it
// file: can't begin and end with slash
// star (*) and question mark(?) are reserved only for matching
func IsValidKey(key string, allowMatchCharacters bool, isDir bool) *exterror.Error {

	if len(key) == 0 {
		return exterror.NewUnprocessableEntityWrap(shared.ErrKeyNameSyntaxError).SetComment(shared.ErrKeyNameSyntaxError.Error())
	}

	var fail bool
	var prevCh int32
	for i, c := range key {
		if c == '#' || c == '|' {
			fail = true
			break
		}
		if c == '?' || c == '*' {
			if allowMatchCharacters {
				for _, c2 := range key {
					if c2 == ' ' {
						return exterror.NewUnprocessableEntityWrap(shared.ErrKeyNameSyntaxError).SetComment(shared.ErrKeyNameSyntaxError.Error())
					}
				}
				return nil
			} else {
				fail = true
				break
			}
		}

		if c == '/' {
			if prevCh == '/' {
				fail = true
			}
			// can't start with trailing slash
			if i == 0 {
				fail = true
				break
			}
			// can't end with trailing slash if is not dir
			if i == len(key)-1 && !isDir {
				fail = true
				break
			}
		}
	}

	if isDir {
		if fail || !matchLinuxDirWithoutSpaces.MatchString("/"+key) {
			return exterror.NewUnprocessableEntityWrap(shared.ErrKeyNameSyntaxError).SetComment(shared.ErrKeyNameSyntaxError.Error())
		}
	} else {
		if fail || !matchLinuxPathWithoutSpaces.MatchString("/"+key) {
			return exterror.NewUnprocessableEntityWrap(shared.ErrKeyNameSyntaxError).SetComment(shared.ErrKeyNameSyntaxError.Error())
		}

	}

	return nil
}

var matchLinuxDirWithoutSpaces = regexp.MustCompile(`^(/[^/ ]*)+/$`)
var matchLinuxPathWithoutSpaces = regexp.MustCompile(`^(/[^/ ]*)+/?$`)

func copyFileFromReader(r io.Reader, dst string) (written int64, err *exterror.Error) {
	out, e := os.Create(dst)
	if e != nil {
		err = exterror.NewInternalServerWrap(e)
		return
	}
	defer func() {
		cerr := out.Close()
		if err == nil && cerr != nil {
			err = exterror.NewUnprocessableEntityWrap(cerr)
		}
	}()

	written, e = io.Copy(out, r)
	if e == nil {
		e = out.Sync()
	}
	if e != nil {
		err = exterror.NewInternalServerWrap(e)
	}
	return
}

func ToJson(val interface{}) string {
	dat, err := json.Marshal(val)
	if err != nil {
		return ""
	}
	return string(dat)
}

func ToFileInfo(value string) (*shared.FileInfo, *exterror.Error) {
	if len(value) == 0 {
		return nil, exterror.NewInternalServerWrap(errors.New("fileinfo value is empty"))
	}
	var fi shared.FileInfo
	if err := json.Unmarshal([]byte(value), &fi); err != nil {
		return nil, exterror.NewInternalServerWrap(fmt.Errorf("file info is invalid: %v", err))
	} else {
		if _, err := fi.Id(); err != nil {
			return nil, err
		}
		return &fi, nil
	}
}

// formatExpirationTime
// @value number:[year|month|week|day|hour|minute|second]
// @return time in future or error
func formatExpirationTime(value string, now time.Time) (time.Time, *exterror.Error) {

	var idx int = 0
	for i, c := range value {
		if c > '9' {
			idx = i
			break
		}
	}
	if idx < 1 {
		return time.Time{}, exterror.NewUnprocessableEntity().SetCommentf("invalid expiration time: %v", value)
	}

	count, err := strconv.ParseInt(value[:idx], 10, 32)
	if err != nil || count <= 0 {
		return time.Time{}, exterror.NewUnprocessableEntity().SetCommentf("formatting expiration time %v: %v", value, err)
	}
	switch value[idx:] {
	case "year":
		return now.AddDate(int(count), 0, 0), nil
	case "month":

		return now.AddDate(0, int(count), 0), nil
	case "week":
		return now.AddDate(0, 0, int(count*7)), nil
	case "day":
		return now.AddDate(0, 0, int(count)), nil
	case "hour":
		break
		return now.Add(time.Duration(count) * time.Hour), nil
	case "minute":
		return now.Add(time.Duration(count) * time.Minute), nil
		break
	case "second":
		return now.Add(time.Duration(count) * time.Second), nil
		break
	}
	return time.Time{}, exterror.NewUnprocessableEntity().SetCommentf("formatting expiration time unrecognized durration %v: %v", value, err)
}

const sniffLen = 512

// DetectContentType recognize content type from file extension or first bytes
// based on net/http
// The algorithm uses at most sniffLen bytes to make its decision.
func DetectContentType(filename string, seeker io.ReadSeeker) (string, *exterror.Error) {
	retType := mime.TypeByExtension(filepath.Ext(filename))
	if retType == "" {
		// read a chunk to decide between utf-8 text and binary
		var buf [sniffLen]byte
		n, err := io.ReadFull(seeker, buf[:])
		if err != nil {
			return "", exterror.NewInternalServerWrap(err)
		}
		// rewind to output whole file
		if _, err = seeker.Seek(0, io.SeekStart); err != nil {
			return "", exterror.NewInternalServerWrap(fmt.Errorf("seeker can't seek %v", err.Error()))
		}
		retType = http.DetectContentType(buf[:n])
	}

	return retType, nil
}

func HashText(value string) string {
	var empty bool
	if len(value) == 0 {
		empty = true
		value = time.Now().String()
	}
	// Create sha-512 hasher
	var hasher = sha256.New()
	hasher.Write([]byte(value))
	hashedBytes := hasher.Sum(nil)
	if empty {
		return "*" + hex.EncodeToString(hashedBytes)
	}
	return hex.EncodeToString(hashedBytes)
}

//var pathMatch = regexp.MustCompile(`^(/[a-zA-Z0-9_-]+\/?)*$`)

var sliceOfString = pull.New(func() []string {
	return make([]string, 0, 1024)
}, func(val []string) []string {
	return val[:0]
})
