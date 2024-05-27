package main

import (
	"errors"
	"log"
	"net"
)

func contains(list []string, value string) bool {
	for _, val := range list {
		if val == value {
			return true
		}
	}
	return false
}

func ParseIPAddress(straddress string) (net.IP, string) {
	parsedaddress := net.ParseIP(straddress)
	var address net.IP
	family, err := GetIPAddressFamily(straddress)
	if err == nil {
		if family == "ipv4" {
			address = parsedaddress.To4()
		} else if family == "ipv6" {
			address = parsedaddress.To16()
		} else {
			log.Println("unknown family, this should not happen")
			return nil, family
		}
		return address, family
	}
	log.Println("address parsing failed:", err)
	return nil, ""
}

func AddressFamilyToSetName(set string, family string) string {
	if family == "ipv4" {
		return set + "4"
	} else if family == "ipv6" {
		return set + "6"
	}
	log.Println("illegal family")
	return ""
}


func GetIPAddressFamily(ip string) (string, error) {
	if net.ParseIP(ip) == nil {
		return "", errors.New("Not an IP address")
	}
	for i := 0; i < len(ip); i++ {
		switch ip[i] {
		case '.':
			return "ipv4", nil
		case ':':
			return "ipv6", nil
		}
	}

	return "", errors.New("unknown error")
}
