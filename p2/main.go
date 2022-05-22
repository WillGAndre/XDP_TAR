package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"path/filepath"
)

func main() {
	text := "Create xdp config files:\n" +
		"\t[1] Block by protocol" +
		"\t\t -> Protocols must follow nomenclature as stated in: redbpf_probes::bindings::IPPROTO_" +
		"" +
		"" +
		"\n"
	fmt.Println(text)
	fmt.Print("> ")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if scanner.Text() == "1" {
			path := filepath.Join("src", "fw", "block-proto")
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

			break
		}
	}
}
