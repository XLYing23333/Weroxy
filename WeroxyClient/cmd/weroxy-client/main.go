// Command weroxy-client runs a Weroxy v1 tunnel and manages native services.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	notices "weroxy/client"

	"weroxy/client/internal/buildinfo"
	"weroxy/client/internal/clientservice"
	"weroxy/client/internal/config"
	"weroxy/client/internal/doctor"
	"weroxy/client/internal/harden"
	"weroxy/client/internal/menu"
	"weroxy/client/internal/status"
	"weroxy/client/internal/tunnel"
	"weroxy/client/internal/upgrade"
)

// commandStdin is os.Stdin except in tests of --key-stdin.
var commandStdin io.Reader = os.Stdin

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	for _, arg := range args {
		if arg == "--key" || strings.HasPrefix(arg, "--key=") || arg == "--token" || strings.HasPrefix(arg, "--token=") {
			fmt.Fprintln(os.Stderr, "Key or Token must not be supplied in command arguments.")
			return 2
		}
	}
	if len(args) == 1 && args[0] == "version" {
		fmt.Println("weroxy-client", buildinfo.Version)
		return 0
	}
	if len(args) == 0 {
		return runMenu(nil)
	}
	switch args[0] {
	case "notices":
		if len(args) != 1 {
			return 2
		}
		fmt.Fprint(os.Stdout, notices.Text())
		return 0
	case "purge-profile":
		if os.Geteuid() != 0 {
			return 1
		}
		path, _, err := clientFlags(args[1:])
		if err != nil || path == "" {
			return 2
		}
		if err = config.Purge(path); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if filepath.Clean(path) != status.InstalledConfigPath {
			if err = config.Purge(status.InstalledConfigPath); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
		}
		return 0
	case "profile-init":
		if len(args) != 1 {
			return 2
		}
		path, err := config.DefaultUserPath()
		if err == nil {
			err = config.EnsureUserProfile(path)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "The user profile needs repair; use profile:", err)
		}
		fmt.Fprintln(os.Stdout, "User profile: ", path)
		return 0
	case "init":
		return runInit(args[1:])
	case "run":
		return runTunnel(args[1:])
	case "harden":
		return runHarden(args[1:])
	case "doctor":
		return runDoctor(args[1:])
	case "status":
		return runStatus(args[1:])
	case "upgrade":
		return runUpgrade(args[1:])
	case "menu":
		return runMenu(args[1:])
	case "service":
		return runService(args[1:])
	case "allow":
		fmt.Fprintln(os.Stderr, "0.3.0: target authorization is managed in Server Web; allow was removed.")
		return 2
	default:
		fmt.Fprintln(os.Stderr, "usage: weroxy-client version|notices|upgrade --package <path> --sha256 <hex> --version <version> [--config <path>]|status [--config <path>] [--json]|doctor --config <path> [--json]|init --config <path> --host <host> --key-stdin|run --config <path>|menu --config <path>|service <action> [--config <path>]")
		return 2
	}
}

func runInit(args []string) int {
	for _, arg := range args {
		if strings.HasPrefix(arg, "--cert") || strings.HasPrefix(arg, "--allow-target") {
			fmt.Fprintln(os.Stderr, "Certificate and local allow options are not supported; configure Host/Port/Key only.")
			return 2
		}
	}
	path, host, port, _, err := initFlags(args)
	if err != nil || path == "" || host == "" {
		fmt.Fprintln(os.Stderr, "init requires --config --host --key-stdin; optional --port defaults to 29999")
		return 2
	}
	token, err := config.ReadToken(commandStdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to read the token.")
		return 2
	}
	defer zero(token)
	if err := config.Save(path, host, hex.EncodeToString(token), port); err != nil {
		fmt.Fprintln(os.Stderr, "Profile not saved: ", err)
		return 1
	}
	fmt.Fprintln(os.Stdout, "Profile saved. Configure forwards in Server Web, then start Client.")
	return 0
}

func runTunnel(args []string) int {
	path, keyStdin, err := clientFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 2
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "usage: weroxy-client run --config <path>")
		return 2
	}
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Configuration error: ", err)
		return 2
	}
	var token []byte
	if keyStdin {
		token, err = config.ReadToken(commandStdin)
	} else {
		token, err = config.ReadToken(strings.NewReader(cfg.Key))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to read the token.")
		return 2
	}
	defer zero(token)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	err = clientservice.Run(ctx, tunnel.Options{Config: cfg, Token: token, StatusPath: status.Path(path)})
	zero(token)
	if errors.Is(err, tunnel.ErrRejected) {
		fmt.Fprintln(os.Stderr, "Credentials rejected; reconnection stopped.")
		return 78 // EX_CONFIG: systemd must not restart rejected credentials.
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "Connection failed; use doctor to check configuration, ports and permissions.")
		return 1
	}
	return 0
}

func runUpgrade(args []string) int {
	values := map[string]string{"--config": status.InstalledConfigPath}
	for i := 0; i < len(args); i++ {
		name, value, hasValue := strings.Cut(args[i], "=")
		if name != "--package" && name != "--previous-package" && name != "--previous-sha256" && name != "--sha256" && name != "--version" && name != "--config" {
			fmt.Fprintln(os.Stderr, "unknown upgrade option")
			return 2
		}
		if !hasValue {
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "missing upgrade option value")
				return 2
			}
			i++
			value = args[i]
		}
		values[name] = value
	}
	if values["--package"] == "" || values["--sha256"] == "" || values["--version"] == "" {
		fmt.Fprintln(os.Stderr, "usage: weroxy-client upgrade --package <path> --sha256 <hex> --version <version> [--config <path>]")
		return 2
	}
	if os.Geteuid() != 0 {
		argv := append([]string{"--", menu.ServiceBinaryPath, "upgrade"}, args...)
		cmd := exec.Command("sudo", argv...)
		cmd.Stdin = commandStdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return 1
		}
		return 0
	}
	fmt.Fprintln(os.Stdout, "Upgrade preserves service and autostart states. A running service will restart and existing connections may be interrupted.")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := upgrade.ApplyPackage(ctx, values["--package"], values["--sha256"], values["--version"], values["--config"], values["--previous-package"], values["--previous-sha256"]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}
	fmt.Fprintln(os.Stdout, "Upgrade complete; service state preserved. The previous package is in /var/cache/weroxy-client.")
	return 0
}

func runStatus(args []string) int {
	path := status.InstalledConfigPath
	jsonOutput := false
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--config" && i+1 < len(args):
			i++
			path = args[i]
		case strings.HasPrefix(args[i], "--config="):
			path = strings.TrimPrefix(args[i], "--config=")
		case args[i] == "--json":
			jsonOutput = true
		default:
			fmt.Fprintln(os.Stderr, "usage: weroxy-client status [--config <path>] [--json]")
			return 2
		}
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "Configuration path must not be empty.")
		return 2
	}
	snap, running := status.Read(status.Path(path))
	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(struct {
			State     string `json:"state"`
			Running   bool   `json:"running"`
			Connected bool   `json:"connected"`
			UpBytes   uint64 `json:"up_bytes"`
			DownBytes uint64 `json:"down_bytes"`
		}{State: status.SafeState(snap.State), Running: running, Connected: snap.Connected, UpBytes: snap.Up, DownBytes: snap.Down})
	} else if !running {
		if _, err := config.Load(path); err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintln(os.Stdout, "Not configured; use the menu to set up the connection.")
			} else {
				fmt.Fprintln(os.Stdout, "Unable to read configuration; check its path, key file and permissions.")
			}
		}
		fmt.Fprintln(os.Stdout, "Client is offline or its protected status is not readable. Use service status and doctor for diagnostics.")
	} else {
		state := status.StateText(snap.State)
		if snap.Connected {
			state = "Connected"
		}
		fmt.Fprintf(os.Stdout, "Client running; control: %s; upload: %d bytes; download: %d bytes\n", state, snap.Up, snap.Down)
	}
	if !running {
		return 1
	}
	return 0
}

func runDoctor(args []string) int {
	var path string
	jsonOutput := false
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--config" && i+1 < len(args):
			i++
			path = args[i]
		case strings.HasPrefix(args[i], "--config="):
			path = strings.TrimPrefix(args[i], "--config=")
		case args[i] == "--json":
			jsonOutput = true
		default:
			fmt.Fprintln(os.Stderr, "usage: weroxy-client doctor --config <path> [--json]")
			return 2
		}
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "usage: weroxy-client doctor --config <path> [--json]")
		return 2
	}
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to read the protected configuration.")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	report := doctor.Run(ctx, cfg)
	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(report)
	} else {
		for _, check := range report.Hardening {
			fmt.Fprintf(os.Stdout, "%s: %s — %s\n", check.Label(), check.Status, check.Detail)
		}
		for _, check := range report.Checks {
			fmt.Fprintf(os.Stdout, "%s: %s — %s\n", check.Name, check.Status, check.Detail)
		}
	}
	if !report.OK {
		return 1
	}
	return 0
}

func runMenu(args []string) int {
	if runtime.GOOS == "windows" {
		return runWindowsMenu(args)
	}
	path, _, err := clientFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 2
	}
	if !menu.IsTerminal() {
		return menu.Run(context.Background(), menu.Option{})
	}
	if path == "" {
		path, err = defaultMenuConfig()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Unable to locate the user profile directory; specify --config.")
			return 2
		}
		if err := config.EnsureUserProfile(path); err != nil {
			fmt.Fprintln(os.Stderr, "The user profile needs repair; use profile:", err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return menu.Run(ctx, menu.Option{ConfigPath: path, Action: func(action string, values []string) int {
		switch action {
		case "harden":
			return runHarden(values)
		case "doctor":
			return runDoctor([]string{"--config", path})
		case "run":
			return runTunnel([]string{"--config", path})
		case "upgrade":
			// Upgrade validates the installed service profile, not the menu's
			// selectable per-user profile.
			return runUpgrade([]string{"--package", values[0], "--sha256", values[1], "--version", values[2], "--previous-package", values[3], "--previous-sha256", values[4]})
		default:
			return 2
		}
	}})
}

func runService(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: weroxy-client service <install|enable|disable|start|stop|restart|status|uninstall> [--config <path>]")
		return 2
	}
	path, keyStdin, err := clientFlags(args[1:])
	if err != nil || keyStdin {
		fmt.Fprintln(os.Stderr, "invalid service options")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return clientservice.Manage(ctx, args[0], path)
}

func initFlags(args []string) (path, host, port, cert string, err error) {
	port = config.ControlPort
	keyStdin := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		take := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("missing value for %s", arg)
			}
			i++
			return args[i], nil
		}
		switch {
		case arg == "--config" || strings.HasPrefix(arg, "--config="):
			path, err = flagArg(arg, "--config", take)
		case arg == "--host" || strings.HasPrefix(arg, "--host="):
			host, err = flagArg(arg, "--host", take)
		case arg == "--port" || strings.HasPrefix(arg, "--port="):
			port, err = flagArg(arg, "--port", take)
		case arg == "--cert" || strings.HasPrefix(arg, "--cert="):
			cert, err = flagArg(arg, "--cert", take)
		case arg == "--key-stdin":
			keyStdin = true
		default:
			return "", "", "", "", fmt.Errorf("unknown flag %s", arg)
		}
		if err != nil {
			return "", "", "", "", err
		}
	}
	if !keyStdin {
		return "", "", "", "", errors.New("init requires --key-stdin")
	}
	return path, host, port, cert, nil
}

func flagArg(arg, name string, take func() (string, error)) (string, error) {
	if arg == name {
		return take()
	}
	return strings.TrimPrefix(arg, name+"="), nil
}

func clientFlags(args []string) (string, bool, error) {
	var path string
	keyStdin := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--config":
			if i+1 >= len(args) {
				return "", false, errors.New("missing value for --config")
			}
			path = args[i+1]
			i++
		case strings.HasPrefix(arg, "--config="):
			path = strings.TrimPrefix(arg, "--config=")
		case arg == "--key-stdin":
			keyStdin = true
		default:
			return "", false, fmt.Errorf("unknown flag %s", arg)
		}
	}
	return path, keyStdin, nil
}

func zero(token []byte) {
	for i := range token {
		token[i] = 0
	}
}

// The menu edits the per-user profile; service synchronization is explicit.
func defaultMenuConfig() (string, error) {
	return config.DefaultUserPath()
}

func runHarden(args []string) int {
	write := len(args) > 0 && args[0] != "status"
	for _, a := range args {
		if a == "--dry-run" {
			write = false
		}
	}
	if write && runtime.GOOS == "linux" && os.Geteuid() != 0 {
		exe, err := os.Executable()
		if err != nil {
			return 1
		}
		cmd := exec.Command("sudo", append([]string{"--preserve-env=SSH_CONNECTION", exe, "harden"}, args...)...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err = cmd.Run(); err != nil {
			return 1
		}
		return 0
	}
	return harden.Run(args, os.Stdin, os.Stdout)
}
