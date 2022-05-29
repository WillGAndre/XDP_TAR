package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// IPv4 integer conv source: http://www.aboutmyip.com/AboutMyXApp/IP2Integer.jsp?ipAddress=142.250.184.174

func main() {
	boot := "Blocker:\n" +
		"\t[b] build\n" +
		"\t[l] load" +
		"\t\t\t -> ex: enp0s10\n" +
		"\n" +
		"\t--------\n" +
		"\n" +
		"Create config files:\n" +
		"\t[1] Block by protocol" +
		"\t\t -> Protocols must follow nomenclature as stated in: redbpf_probes::bindings::IPPROTO_\n" +
		"\t[2] Block by ipv4" +
		"\t\t -> Ips must follow CIDR notation\n" +
		"\t[3] Block by port\n" +
		"\t[4] Block by TCP flag\n" +
		"" +
		"\n" +
		"\t[c] clear\n" +
		"\n" +
		"\n" +
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
		}
		if scanner.Text() == "4" {
			path = filepath.Join("src", "fw", "block-tcp-flags")
			os.Truncate(path, 0)
			f, err := os.Create(path)

			if err != nil {
				log.Fatal(err)
			}

			defer f.Close()

			text = "Set TCP flag:\n" +
				"\tflags: res1 doff fin syn rst psh ack urg"
			fmt.Println(text)
			for scanner.Scan() {
				if scanner.Text() != "\n" {
					f_res := "["
					flags := scanner.Text()
					flags_split := strings.Split(flags, " ")
					flags_res := set_flags(flags_split)
					for i, r := range flags_res {
						f_res += strconv.Itoa(r)
						if i+1 != len(flags_res) {
							f_res += ", "
						}
					}
					f_res += "]"
					f.WriteString(f_res)
					break
				}
			}

			fmt.Print(boot)
		}
		if scanner.Text() == "b" {
			build := exec.Command("sudo", "cargo", "bpf", "build")
			out, err := build.Output()

			if err != nil {
				log.Fatal(err)
			}

			fmt.Print(string(out))
			fmt.Print("\n")
			fmt.Print(boot)
		}
		if scanner.Text() == "l" {
			fmt.Println("Interface: ")
			for scanner.Scan() {
				if scanner.Text() != "\n" {
					itf := scanner.Text()
					load := exec.Command("sudo", "cargo", "bpf", "load", "-i", itf, "target/bpf/programs/fw/fw.elf")
					out, err := load.Output()

					if err != nil {
						log.Fatal(err)
					}

					fmt.Print(string(out))
					fmt.Print("\n")
					fmt.Print(boot)
				}
			}
		}
		if scanner.Text() == "c" {
			path = filepath.Join("src", "fw", "block-proto")
			clear(path, 1)
			path = filepath.Join("src", "fw", "block-ip")
			clear(path, 2)
			path = filepath.Join("src", "fw", "block-port")
			clear(path, 3)
			path = filepath.Join("src", "fw", "block-tcp-flags")
			clear(path, 4)

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
		f.WriteString("[80]")
	} else if opt == 4 {
		f.WriteString("[0,0,0,0,0,0,0,0]")
	}
}

func set_flags(flags []string) []int {
	res := []int{0, 0, 0, 0, 0, 0, 0, 0}
	for _, flag := range flags {
		i := contains(flag)
		if i != -1 {
			res[i] = 1
		}
	}
	return res
}

func contains(query string) int {
	const_flags := []string{"res1", "doff", "fin", "syn", "rst", "psh", "ack", "urg"}
	for i, flag := range const_flags {
		if flag == query {
			return i
		}
	}
	return -1
}
