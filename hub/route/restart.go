package route

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/Dreamacro/clash/log"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func restartRouter() http.Handler {
	r := chi.NewRouter()
	r.Post("/", restart)
	return r
}

func restart(w http.ResponseWriter, r *http.Request) {
	// modify from https://github.com/AdguardTeam/AdGuardHome/blob/595484e0b3fb4c457f9bb727a6b94faa78a66c5f/internal/home/controlupdate.go#L180
	execPath, err := os.Executable()
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError(fmt.Sprintf("getting path: %s", err)))
		return
	}

	if runtime.GOOS == "windows" {
		cmd := exec.Command(execPath, os.Args[1:]...)
		log.Infoln("restarting: %q %q", execPath, os.Args[1:])
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Start()
		if err != nil {
			log.Fatalln("restarting:: %s", err)
		}

		os.Exit(0)
	}

	log.Infoln("restarting: %q %q", execPath, os.Args[1:])
	err = syscall.Exec(execPath, os.Args, os.Environ())
	if err != nil {
		log.Fatalln("restarting: %s", err)
	}

	render.JSON(w, r, render.M{"status": "ok"})
}
