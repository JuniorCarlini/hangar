package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"golang.org/x/term"
	"rsc.io/qr"

	"github.com/JuniorCarlini/hangar/internal/app"
	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/i18n"
)

// userCmd manages users from the server's command line. It is also a way to
// create the first owner (the other is the first-run page, open for a while
// after start); either one closes the first-run page.
func userCmd(ctx context.Context, args []string, stdout, stderr io.Writer, log *slog.Logger) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, tr("cli.user.usage"))
		return i18n.E("cli.missing_subcommand")
	}
	fs := flag.NewFlagSet("hangard user "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "/etc/hangar/hangar.toml", tr("cli.flag_config"))
	email := fs.String("email", "", tr("cli.user.flag_email"))
	role := fs.String("role", "owner", tr("cli.user.flag_role"))
	no2FA := fs.Bool("no-2fa", false, tr("cli.user.flag_no_2fa"))
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *email == "" {
		return i18n.E("cli.user.email_required")
	}
	cfg, err := loadConfigFile(*cfgPath)
	if err != nil {
		return err
	}
	core, err := app.Open(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer func() { _ = core.Close() }()
	in := newPrompter(stdout)

	switch args[0] {
	case "create":
		r, err := auth.ParseRole(*role)
		if err != nil {
			return err
		}
		password, err := in.newPassword(*email)
		if err != nil {
			return err
		}
		id, err := core.Auth.CreateUser(ctx, *email, password, r)
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, "\n"+tr("cli.user.created", "email", *email, "role", r.String()))
		if *no2FA {
			// The panel's setting decides (owners and admins always need
			// 2FA): such an account enrolls right after signing in.
			if core.Auth.RequiredFor(ctx, r) {
				fmt.Fprintln(stdout, tr("cli.user.no_2fa_required"))
			} else {
				fmt.Fprintln(stdout, tr("cli.user.no_2fa"))
			}
			return nil
		}
		return enrollTOTP(ctx, core.Auth, id, *email, in, stdout)

	case "totp":
		id, err := core.Auth.UserIDByEmail(ctx, *email)
		if err != nil {
			return err
		}
		return enrollTOTP(ctx, core.Auth, id, *email, in, stdout)

	case "totp-off":
		if err := core.Auth.ResetTOTP(ctx, *email); err != nil {
			return err
		}
		fmt.Fprintln(stdout, tr("cli.user.totp_off", "email", *email))
		fmt.Fprintln(stdout, tr("cli.user.no_2fa_required"))
		return nil

	case "password":
		if _, err := core.Auth.UserIDByEmail(ctx, *email); err != nil {
			return err
		}
		password, err := in.newPassword(*email)
		if err != nil {
			return err
		}
		if err := core.Auth.ResetPassword(ctx, *email, password); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "\n"+tr("cli.user.password_reset", "email", *email))
		return nil

	case "unlock":
		if err := core.Auth.Unlock(ctx, *email); err != nil {
			return err
		}
		fmt.Fprintln(stdout, tr("cli.user.unlocked", "email", *email))
		return nil
	}
	fmt.Fprint(stderr, tr("cli.user.usage"))
	return i18n.E("cli.unknown_subcommand", "command", args[0])
}

// enrollTOTP shows the QR code, checks a code from the app and generates the
// recovery codes. The secret is only stored after the check.
func enrollTOTP(ctx context.Context, svc *auth.Service, userID, email string, in *prompter, out io.Writer) error {
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		return err
	}
	uri := auth.TOTPURI("Hangar", email, secret)

	fmt.Fprintln(out, "\n"+tr("cli.totp.scan"))
	fmt.Fprintln(out)
	if err := printQR(out, uri); err != nil {
		return err
	}
	fmt.Fprintln(out, "\n"+tr("cli.totp.manual", "secret", secret)+"\n")

	for attempt := 1; ; attempt++ {
		code, err := in.line(tr("cli.totp.prompt") + " ")
		if err != nil {
			return err
		}
		err = svc.EnrollTOTP(ctx, userID, secret, code)
		if err == nil {
			break
		}
		if !errors.Is(err, auth.ErrInvalidCode) || attempt == 3 {
			return err
		}
		fmt.Fprintln(out, tr("cli.totp.mismatch"))
	}

	codes, err := svc.NewRecoveryCodes(ctx, userID)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "\n"+tr("cli.totp.enabled"))
	fmt.Fprintln(out)
	for _, c := range codes {
		fmt.Fprintf(out, "    %s\n", c)
	}
	fmt.Fprintln(out, "\n"+tr("cli.totp.keep_codes"))
	return nil
}

// printQR draws the QR code in the terminal with half blocks (two code rows
// per text line), with a white margin so scanners can find it.
func printQR(out io.Writer, text string) error {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return err
	}
	const quiet = 2
	size := code.Size
	dark := func(x, y int) bool {
		if x < 0 || y < 0 || x >= size || y >= size {
			return false
		}
		return code.Black(x, y)
	}
	var b strings.Builder
	for y := -quiet; y < size+quiet; y += 2 {
		b.WriteString("  ")
		for x := -quiet; x < size+quiet; x++ {
			top, bottom := dark(x, y), dark(x, y+1)
			switch {
			case top && bottom:
				b.WriteRune(' ')
			case top:
				b.WriteRune('▄')
			case bottom:
				b.WriteRune('▀')
			default:
				b.WriteRune('█')
			}
		}
		b.WriteRune('\n')
	}
	_, err = io.WriteString(out, b.String())
	return err
}

type prompter struct {
	out    io.Writer
	reader *bufio.Reader
	tty    bool
}

func newPrompter(out io.Writer) *prompter {
	return &prompter{out: out, reader: bufio.NewReader(os.Stdin), tty: term.IsTerminal(int(os.Stdin.Fd()))} //nolint:gosec // file descriptor fits in int
}

func (p *prompter) line(prompt string) (string, error) {
	fmt.Fprint(p.out, prompt)
	s, err := p.reader.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || s == "") {
		return "", err
	}
	return strings.TrimSpace(s), nil
}

func (p *prompter) secret(prompt string) (string, error) {
	if !p.tty {
		return p.line(prompt) // redirected input (installer, tests)
	}
	fmt.Fprint(p.out, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd())) //nolint:gosec // file descriptor fits in int
	fmt.Fprintln(p.out)
	return string(b), err
}

func (p *prompter) newPassword(email string) (string, error) {
	fmt.Fprintln(p.out, tr("cli.password.intro", "min", auth.MinPasswordLen))
	for range 3 {
		pw, err := p.secret("  " + tr("cli.password.prompt") + " ")
		if err != nil {
			return "", err
		}
		if err := auth.CheckPasswordStrength(pw, email); err != nil {
			fmt.Fprintln(p.out, " ", i18n.Message(loc, err))
			continue
		}
		again, err := p.secret("  " + tr("cli.password.repeat") + " ")
		if err != nil {
			return "", err
		}
		if pw != again {
			fmt.Fprintln(p.out, "  "+tr("cli.password.mismatch"))
			continue
		}
		return pw, nil
	}
	return "", i18n.E("cli.password.not_set")
}
