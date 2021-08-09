package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/terassyi/godns"
)

const (
	RESOLV_CON_PATH string = "/etc/resolv.conf"
	PORT int = 53
)

func main() {
	dst := ""
	if len(os.Args) > 1 {
		dst = os.Args[1]
	}
	fmt.Println("; <<>> go DiG <<>> ", dst)

	resolvers, err := getResolverAddr()
	if err != nil || len(resolvers) < 1 {
		fmt.Println(";; Cannot find resolver from /etc/resolv.conf")
	}
	repBuf, err := request(resolvers[0], dst)
	if err != nil {
		fmt.Printf(";; %v\n", err)
	}
	rep, err := godns.NewPacket(repBuf)
	if err != nil {
		os.Exit(1)
	}
	fmt.Println(";; Got answer:")
	status := ""
	if rep.Header.RCode == godns.NoError {
		status = "NOERROR"
	} else {
		status = fmt.Sprintf("%v", rep.Header.RCode)
	}
	fmt.Printf(";; ->>HEADER<<- opcode: %s, status: %v, id: %x\n", rep.Header.Opcode.String(), status, rep.Header.Id)
	flag := ""
	if rep.Header.Qr {
		flag += "qr "
	}
	if rep.Header.AA {
		flag += "aa "
	}
	if rep.Header.TC {
		flag += "tc "
	}
	if rep.Header.RD {
		flag += "rd "
	}
	if rep.Header.RA {
		flag += "ra "
	}
	if rep.Header.AD {
		flag += "ad "
	}
	if rep.Header.CD {
		flag += "cd "
	}
	fmt.Printf(";; flags: %s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n", flag, rep.Header.Qdcount, rep.Header.Ancount, rep.Header.Nscount, rep.Header.Arcount)

	fmt.Println(";; QUESTION SECTION:")
	question := rep.Questions[0]
	fmt.Printf(";%s\t\t%s\t%s\n", question.Domain.String(), question.Class.String(), question.Type.String())
	fmt.Println()
	fmt.Println(";; ANSWER SECTION:")
	for _, ans := range rep.Answers {
		addr := net.IP(ans.Rdata)
		fmt.Printf("%s\t\t%s\t%s\t%v\n", ans.Domain.String(), ans.Class.String(), ans.Type.String(), addr.String())
	}
	fmt.Printf(";; SERVER: %s#%d(%s)", resolvers[0], PORT, resolvers[0])
	os.Exit(0)
}

func getResolverAddr() ([]string, error) {
	slist := make([]string, 0)
	file, err := os.Open(RESOLV_CON_PATH)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line[0] == 0x23 {
			continue
		}
		if strings.Contains(line, "nameserver") {
			l := strings.Split(line, " ")
			slist = append(slist, l[1])
		}
	}
	return slist, nil
}

func request(resolver, domain string) ([]byte, error) {
	host := fmt.Sprintf("%s:%d", resolver, PORT)
	conn, err := net.Dial("udp", host)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	p, err := buildDNSPacket(domain)
	if err != nil {
		return nil, err
	}
	p.Header.Show()
	data, err := p.Serialize()
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(data); err != nil {
		return nil, err
	}
	repBuf := make([]byte, 1024)
	if _, err := conn.Read(repBuf); err != nil {
		return nil, err
	}
	return repBuf, nil
}

func buildDNSPacket(domain string) (*godns.Packet, error) {
	packet := &godns.Packet{}
	header := &godns.Header{}
	header.Id = 0x8888
	header.Qr = false
	header.Opcode = godns.QUERY
	header.AA = false
	header.TC = false
	header.RD = true
	header.RA = false
	header.AD = false
	header.CD = false
	header.Qdcount = 1
	header.Ancount = 0
	header.Nscount = 0
	header.Arcount = 0
	header.RCode = godns.NoError
	packet.Header = *header
	q, err := godns.NewQuestion(domain, godns.A, godns.IN)
	if err != nil {
		return nil, err
	}
	packet.Questions = []godns.Question{*q}

	return packet, nil
}
