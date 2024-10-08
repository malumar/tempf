package main

import (
	"flag"
	"fmt"
	"github.com/malumar/fileserver/internal/webserver"
	"github.com/malumar/fileserver/pkg/fileserver"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

var resetApiKey bool
var doRun bool
var disabledHandlers string

const (
	EnvironmentKey = "TEMPF_APIKEY"
	MaxUploadSize  = 10 << 20
	MaxMemoryStore = 10024
)

type sliceOfFlag[T any] []T

// String is an implementation of the flag.Value interface
func (i *sliceOfFlag[T]) String() string {
	return fmt.Sprintf("%v", *i)
}

// Set is an implementation of the flag.Value interface
func (i *sliceOfFlag[T]) Set(value T) error {
	*i = append(*i, value)
	return nil
}

func main() {
	flag.Usage = usage
	cfg := fileserver.DefaultConfig()
	var allowlists sliceOfFlag[string]

	flag.StringVar(&cfg.Path, "path", "", "configuration folder, if value is empty, using folder of the application")

	flag.StringVar(&disabledHandlers, "disable", "", fmt.Sprintf("handler names separated by a hyphen to be disabled: %s", strings.Join(webserver.HandlerNames, ", ")))

	flag.BoolVar(&resetApiKey, "resetkey", false, "reset api key")
	flag.Int64Var(&cfg.MaxUploadSize, "maxuploadsize", MaxUploadSize, "max upload bytes, 0 no limit")
	flag.Int64Var(&cfg.MaxMemoryStore, "maxmemstore", MaxMemoryStore, "max file size that defines that it is to be saved directly in the database, if zero never store in db")
	flag.BoolVar(&doRun, "run", false, "start server")
	flag.Var(&allowlists, "allowlist", "proste wyrażenie składające się z * oraz ? pozwalające dopasować elementy które mogą być listowane w przypadku braku autoryzacji")
	_ = flag.NewFlagSet("run", flag.ExitOnError)
	flag.Parse()

	for _, h := range strings.Split(disabledHandlers, ",") {
		if len(h) > 0 {

			cfg.DisabledHandler[h] = true
		}
	}

	for _, item := range allowlists {
		slog.Info("Enable listing match to", "pattern", item)
		cfg.AllowList = append(cfg.AllowList, item)
	}

	if len(cfg.Path) == 0 {
		ex, err := os.Executable()
		if err != nil {
			log.Fatalf("ERR: %v", err.Error())
		}
		exPath := filepath.Dir(ex)

		if si, err := os.Stat(exPath); err == nil {
			if !si.IsDir() {
				log.Fatalf("ERR: config path is not directory: %v\n", exPath)
			}

		} else {
			log.Fatalf("ERR: config path my not exists: %v\n", exPath)
		}
		cfg.Path = exPath

	}

	fs, err := fileserver.New(cfg)
	if err != nil {
		log.Fatalf("ERR: %v", err.Error())
	}

	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		if pair != nil && pair[0] == EnvironmentKey {
			if len(pair[1]) > 0 {
				slog.Info("Setting new api key from environment")
				if err := fs.UpdateApiKey(pair[1]); err != nil {
					log.Fatalf("ERR: %v", err.Error())
				}
				if resetApiKey {
					slog.Warn("Ignoring command resetkey due to setting key from environment")
				}
			} else {
				slog.Warn("Ignoring environment value of key: value is empty")
			}
			break
		}
	}

	if resetApiKey {
		if value, err := fs.ResetApiKey(); err != nil {
			log.Fatalf("ERR: %v", err.Error())
		} else {
			fmt.Println("New ApiKey", value)
		}
	}

	if doRun {
		hfs := webserver.NewHttp(fs)

		if err := hfs.Start(); err != nil {
			log.Fatalf("ERR: %v", err.Error())
		}

	}

}

func usage() {
	w := flag.CommandLine.Output()
	fmt.Fprintf(w, "Usage: %s [OPTIONS] command ...\n", filepath.Base(os.Args[0]))
	fmt.Fprintf(w, "\nCommands:\n")
	fmt.Fprintf(w, " run\n \trun server\n")
	fmt.Fprintf(w, "\t\n")
	fmt.Fprintf(w, "\nOptions:\n")
	flag.PrintDefaults()
}
