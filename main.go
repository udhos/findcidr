package main

import (
	"bufio"
	"fmt"
	"github.com/zmap/go-iptree/iptree"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"unicode"
)

type info struct {
	cidr  string
	block string
	count int
}

var tab = make(map[string]*info)

func split(t *iptree.IPTree, cidr string, plen uint) {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Printf("split: ParseCIDR: %s: %v\n", cidr, err)
		return
	}

	fmt.Printf("# adding CIDR: %s\n", cidr)

	ones, _ := n.Mask.Size()
	blocks := 1 << (plen - uint(ones))
	b := n.IP
	for i := 0; i < blocks; i++ {
		b4 := b.To4()
		v := uint(b4[0])<<24 + uint(b4[1])<<16 + uint(b4[2])<<8 + uint(b4[3])
		v += 1 << (uint(32) - plen)
		v3 := byte(v & 0x000000FF)
		v2 := byte((v >> 8) & 0x000000FF)
		v1 := byte((v >> 16) & 0x000000FF)
		v0 := byte((v >> 24) & 0x000000FF)
		bb := net.IPv4(v0, v1, v2, v3)

		sub := fmt.Sprintf("%s/%d", b, plen)

		//fmt.Printf("split: %s len=%d blocks=%d %s\n", cidr, ones, blocks, sub)

		inf := info{
			cidr:  cidr,
			block: sub,
		}
		t.AddByString(sub, &inf)

		tab[sub] = &inf // record for later display

		b = bb
	}
}

func main() {
	t := iptree.New()
	load(t)
	show(t)
}

func show(t *iptree.IPTree) {
	list := []string{}
	for _, v := range tab {
		//if v.count != 0 {
		list = append(list, fmt.Sprintf("%-16s %-16s = %d\n", v.cidr, v.block, v.count))
		//}
	}
	sort.Strings(list)
	fmt.Println()
	for _, v := range list {
		fmt.Print(v)
	}
}

func load(t *iptree.IPTree) {

	split(t, "10.0.0.0/8", 8)
	split(t, "172.16.0.0/12", 12)
	split(t, "192.168.0.0/16", 16)

	plen := uint(24)

	split(t, "200.99.0.0/16", plen)
	split(t, "200.162.0.0/17", plen)
	split(t, "200.198.64.0/18", plen)
	split(t, "200.202.112.0/20", plen)
	split(t, "201.84.0.0/15", plen)

	fmt.Printf("# reading subnets from stdin - begin\n")

	var lineCount, addrCount, errCount, missCount, defaultCount int

	bio := bufio.NewReader(os.Stdin)

	for {
		str, errStr := bio.ReadString('\n')
		if errStr != nil {
			if errStr != io.EOF {
				fmt.Printf("error: %v line=%d\n", errStr, lineCount)
			}
			break
		}

		lineCount++

		line := strings.Trim(str, "\r\n ")

		if strings.HasPrefix(line, "#") {
			continue
		}

		addrList := strings.FieldsFunc(line, isBlank)

		for _, addr := range addrList {

			addrCount++

			if addr == "0.0.0.0/0" {
				defaultCount++
				continue
			}

			val, found, errGet := t.GetByString(addr)

			if errGet != nil {
				errCount++
				fmt.Printf("%v ERROR: %v line=%d\n", addr, errGet, lineCount)
				continue
			}

			if !found {
				missCount++
				fmt.Printf("%v MISS line=%d\n", addr, lineCount)
				continue
			}

			if inf, isInfo := val.(*info); isInfo {
				inf.count++
				continue
			}
		}
	}

	fmt.Printf("# reading subnets from stdin - done\n")

	fmt.Println()
	fmt.Printf("lineCount        = %d\n", lineCount)
	fmt.Printf("addrCount        = %d\n", addrCount)
	fmt.Printf("errCount         = %d\n", errCount)
	fmt.Printf("missCount        = %d\n", missCount)
	fmt.Printf("defaultCount     = %d\n", defaultCount)
}

func isBlank(c rune) bool {
	return c == '|' || c == '"' || c == 'e' || c == ';' || c == '-' || c == ',' || unicode.IsSpace(c)
}
