package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// IPv4 integer conv source: http://www.aboutmyip.com/AboutMyXApp/IP2Integer.jsp?ipAddress=142.250.184.174

func main() {
	boot := "Create xdp config files:\n" +
		"\t[1] Block by protocol" +
		"\t\t -> Protocols must follow nomenclature as stated in: redbpf_probes::bindings::IPPROTO_\n" +
		"\t[2] Block by ipv4" +
		"\t\t -> Ips must follow CIDR notation\n" +
		"\t[3] Block by port\n" +
		"" +
		"\n\t[c] clear\n" +
		"\t[q] quit\n" +
		"" +
		"" +
		"\n" +
		"> "
	text := boot
	fmt.Print(text)
	scanner := bufio.NewScanner(os.Stdin)
	var path string
	for scanner.Scan() {
		if scanner.Text() == "1" {
			path = filepath.Join("src", "fw", "block-proto")
			os.Truncate(path, 0)
			f, err := os.Create(path)

			if err != nil {
				log.Fatal(err)
			}

			defer f.Close()

			text = "Set protocols as: <PROTOCOL>\n" +
				"\tex: UDP TCP ICMP"
			fmt.Println(text)
			for scanner.Scan() {
				if scanner.Text() != "\n" {
					f_res := "["
					protos := scanner.Text()
					protos_split := strings.Split(protos, " ")
					for i, proto := range protos_split {
						f_res += "IPPROTO_" + proto
						if i+1 != len(protos_split) {
							f_res += ", "
						}
					}
					f_res += "]"
					f.WriteString(f_res)
					break
				}
			}

			fmt.Print(boot)
			// break
		}
		if scanner.Text() == "2" {
			path = filepath.Join("src", "fw", "block-ip")
			os.Truncate(path, 0)
			f, err := os.Create(path)

			if err != nil {
				log.Fatal(err)
			}

			defer f.Close()

			text = "Set IPv4:\n" +
				"\tex: 142.250.184.174"
			fmt.Println(text)
			for scanner.Scan() {
				if scanner.Text() != "\n" {
					f_res := "["
					ips := scanner.Text()
					ips_split := strings.Split(ips, " ")
					for i, ip := range ips_split {
						oct_split := strings.Split(ip, ".")
						var ip_int int
						for j, oct := range oct_split {
							num_oct, err := strconv.Atoi(oct)

							if err != nil {
								log.Fatal(err)
							}

							if j == 0 {
								ip_int += (num_oct * 16777216)
							} else if j == 1 {
								ip_int += (num_oct * 65536)
							} else if j == 2 {
								ip_int += (num_oct * 256)
							} else {
								ip_int += num_oct
							}
						}
						f_res += strconv.Itoa(ip_int) + "_u32"
						if i+1 != len(ips_split) {
							f_res += ", "
						}
					}
					f_res += "]"
					f.WriteString(f_res)
					break
				}
			}

			fmt.Print(boot)
			// break
		}
		if scanner.Text() == "3" {
			path = filepath.Join("src", "fw", "block-port")
			os.Truncate(path, 0)
			f, err := os.Create(path)

			if err != nil {
				log.Fatal(err)
			}

			defer f.Close()

			text = "Set port:\n" +
				"\tex: 443 80 8080"
			fmt.Println(text)
			for scanner.Scan() {
				if scanner.Text() != "\n" {
					f_res := "["
					ports := scanner.Text()
					ports_split := strings.Split(ports, " ")
					for i, port := range ports_split {
						f_res += port
						if i+1 != len(ports_split) {
							f_res += ", "
						}
					}
					f_res += "]"
					f.WriteString(f_res)
					break
				}
			}

			fmt.Print(boot)
		} else if scanner.Text() == "c" {
			path = filepath.Join("src", "fw", "block-proto")
			clear(path, 1)
			path = filepath.Join("src", "fw", "block-ip")
			clear(path, 2)
			path = filepath.Join("src", "fw", "block-port")
			clear(path, 3)

			fmt.Print(boot)
		}
		if scanner.Text() == "q" {
			break
		}
	}
}

func clear(path string, opt int) {
	os.Truncate(path, 0)

	f, err := os.Create(path)

	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	if opt == 1 {
		f.WriteString("[]")
	} else if opt == 2 {
		f.WriteString("[2398795950_u32]")
	} else if opt == 3 {
		f.WriteString("[49150]")
	}
}
