package sudoless

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

type Sudoless struct {
	Files   []*os.File
	pointer uintptr
}

var s = &Sudoless{pointer: 3}

func Port(p int) (net.Listener, error) {
	if havePrivileges() {
		log.Printf("Open port %v", p)
		port, err := net.Listen("tcp", fmt.Sprintf(":%v", p))
		if err != nil {
			return nil, err
		}

		file, err := port.(*net.TCPListener).File()
		if err != nil {
			return nil, err
		}
		s.Files = append(s.Files, file)
		return nil, nil
	} else {
		log.Println("Port Pointer: ", s.pointer)
		port, err := net.FileListener(os.NewFile(s.pointer, "[socket]"))
		s.pointer++
		if err != nil {
			log.Println("Failed to listen ", err)
			os.Exit(1)
		}
		return port, nil
	}
}

func Certs(path string) []tls.Certificate {
	certs := []tls.Certificate{}

	if havePrivileges() {
		log.Println("Searching for certificates in ", path)
		possibleFiles, err := filepath.Glob(path)
		log.Println("Found ", possibleFiles)
		sort.Strings(possibleFiles)

		var certFile, keyFile *os.File
		for i := 0; i < len(possibleFiles)-1; i++ {
			if (strings.HasSuffix(possibleFiles[i], "fullchain.pem") && strings.HasSuffix(possibleFiles[i+1], "privkey.pem")) ||
				(strings.HasSuffix(possibleFiles[i], "server.crt") && strings.HasSuffix(possibleFiles[i+1], "server.key")) {
				certFile, err = os.Open(possibleFiles[i])
				if err != nil {
					log.Fatalf("error loading cert: %v", err)
				}
				log.Println("Found cert " + possibleFiles[i])
				keyFile, err = os.Open(possibleFiles[i+1])
				if err != nil {
					log.Fatalf("error loading key: %v", err)
				}
				log.Println("Found key " + possibleFiles[i+1])
				s.Files = append(s.Files, certFile, keyFile)
				i++
			}
		}
		return certs //Empty

	} else {

		log.Println("Reading cert")
		log.Println("Cert Pointer: ", s.pointer)
		certFile := os.NewFile(s.pointer, "[socket]")
		for certFile != nil {
			log.Println("Cert Pointer: ", s.pointer)
			certFile := os.NewFile(s.pointer, "[socket]")
			log.Println("Reading key")
			log.Println("Key Pointer: ", s.pointer+1)
			keyFile := os.NewFile(s.pointer+1, "[socket]")
			s.pointer += 2

			certBytes, err := ioutil.ReadAll(certFile)
			if err != nil {
				log.Println("Failed to read cert", err)
				break
			}

			keyBytes, err := ioutil.ReadAll(keyFile)
			if err != nil {
				log.Println("Failed to read key", err)
				break
			}

			cert, err := tls.X509KeyPair(certBytes, keyBytes)
			if err != nil {
				log.Fatalf("error building cert: %v", err)
				break
			}
			certs = append(certs, cert)
		}

		return certs
	}
}

func DropPrivileges(u string) error {
	if havePrivileges() {
		log.Println("Dropping privileges...")
		cmd := exec.Command(os.Args[0], os.Args[1:]...)
		log.Println("File D ", s.Files)
		cmd.ExtraFiles = s.Files

		unprivilegedUser, err := user.Lookup(u)
		if err != nil {
			return err
		}
		uid, err := strconv.Atoi(unprivilegedUser.Uid)
		if err != nil {
			return err
		}
		gid, err := strconv.Atoi(unprivilegedUser.Gid)
		if err != nil {
			return err
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid: uint32(uid),
				Gid: uint32(gid),
			},
			Setsid: true,
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Start(); err != nil {
			return err
		}

		err = ioutil.WriteFile(".pid", []byte(strconv.Itoa(cmd.Process.Pid)), 0644)
		if err != nil {
			panic(err)
		}
		cmd.Process.Release()
		os.Exit(0)
		return nil /* unreachable */
	} else {
		return nil
	}
}

func havePrivileges() bool {
	return os.Getuid() == 0
}
