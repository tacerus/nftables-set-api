/*
 * nftables-set-api
 * Copyright (C) 2024 Georg Pfuetzenreuter <mail@georg-pfuetzenreuter.net>
 *
 * based on iptables-api
 * Copyright (C) 2021	The Palner Group, Inc. (palner.com)
 *						Fred Posner (@fredposner)
 *
 * iptables-api is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * iptables-api is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"

  "github.com/google/nftables"
	"github.com/gorilla/mux"
	"github.com/palner/pgrtools/pgparse"
)

var APIport string
var logFile string
var targetTable string
var targetSet string

func init() {
	flag.StringVar(&targetTable, "table", "mytable", "target table")
	flag.StringVar(&targetSet, "set", "myset", "target set prefix")
	flag.StringVar(&logFile, "log", "-", "location of log file or - for stdout")
	flag.StringVar(&APIport, "port", "8082", "port to listen on")
}

func main() {
	flag.Parse()

	if logFile != "-" && logFile != "stdout" {
		lf, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Panic(err)
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			runtime.Goexit()
		}
		defer lf.Close()

		log.SetOutput(lf)
	}

	log.Print("** Starting nftables-API")
	log.Print("** Choose to be optimistic, it feels better.")
	log.Print("** Licensed under GPLv2. See LICENSE for details.")
	log.Print("** API will listen on port ", APIport)

	router := mux.NewRouter()
	router.HandleFunc("/addip/{ipaddress}", addIPAddress).Methods("POST")
	router.HandleFunc("/blockip/{ipaddress}", addIPAddress).Methods("POST")
	router.HandleFunc("/flushchain", flushSet).Methods("GET")
	//router.HandleFunc("/puship/{ipaddress}", pushIPAddress).Methods("GET")
	router.HandleFunc("/removeip/{ipaddress}", removeIPAddress).Methods("POST")
	router.HandleFunc("/unblockip/{ipaddress}", removeIPAddress).Methods("POST")
	router.HandleFunc("/", rHandleIPAddress).Methods("DELETE", "POST", "PUT")
	http.ListenAndServe("[::]:"+APIport, router)
}

// Function to see if string within string
func contains(list []string, value string) bool {
	for _, val := range list {
		if val == value {
			return true
		}
	}
	return false
}

func checkIPAddress(ip string) bool {
	if net.ParseIP(ip) == nil {
		return false
	} else {
		return true
	}
}

func checkIPAddressv4(ip string) (string, error) {
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

func initializeNFTables(nft *nftables.Conn, targetSetF string) (*nftables.Set, error) {
	// Get existing chains from nftables
  foundTables, err := nft.ListTables()
	if err != nil {
		return nil, fmt.Errorf("failed to read nftables: %w", err)
	}

	exists := false
	var table *nftables.Table 
	for _, thistable := range foundTables {
		if thistable.Name == targetTable {
			log.Printf("found %w table", targetTable)
			exists = true
			table = thistable
			break
		}
	}

	if !exists {
		return nil, fmt.Errorf("table %w does not exist", targetTable)
	}

  foundSet, err := nft.GetSetByName(table, targetSetF)
  if err != nil {
		return nil, fmt.Errorf("could not find set %w: %w", targetSetF, err)
	}

	if foundSet == nil {
		log.Printf("nftables set %w not found, creating it now ...", targetSetF)
		set := &nftables.Set{
			Name: targetSetF,
		}
		err := nft.AddSet(set, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create set %w: %w", targetSetF, err)
		}
	} else {
		log.Printf("nftables set %w exists", targetSetF)
		return foundSet, nil
	}

	set, err := nft.GetSetByName(table, targetSetF)
	if err != nil {
		return nil, fmt.Errorf("created set, but cannot find it")
	}

	log.Printf("created set %w", targetSetF)
	return set, nil

}

func nftableHandle(task string, ipvar string) (string, error) {
	log.Println("nftableHandle:", task, ipvar)

	// Go connect for nftables
	nft, err := nftables.New()
	if err != nil {
		log.Println("nftableHandle:", err)
		return "", err
	}

	ipvarparsed := net.ParseIP(ipvar)
	var setname string
	var address net.IP
	family, err := checkIPAddressv4(ipvar)
	if err == nil {
		if family == "ipv4" {
			setname = targetSet + "4"
			address = ipvarparsed.To4()
		} else if family == "ipv6" {
			setname = targetSet + "6"
			address = ipvarparsed.To16()
		}
	} else {
		log.Println("address parsing failed:", err)
	}

	set, err := initializeNFTables(nft, setname)
	if err != nil {
		log.Fatalln("nftableHandler: failed to initialize NFTables:", err)
		return "", err
	}

	element := []nftables.SetElement {
		{
			Key: []byte(address),
		},
	}

	switch task {
	case "add":
		log.Println("nftableHandler: adding address")
		err = nft.SetAddElements(set, element)
		if err != nil {
			log.Println("nftableHandler: error adding address:", err)
			return "", err
		} else {
			err := nft.Flush()
			if err != nil {
				log.Println("nftableHandler: failed to save changes: %w", err)
			}
			return "added", nil
		}
	case "delete":
		log.Println("nftableHandler: deleting address")
		err = nft.SetDeleteElements(set, element)
		if err != nil {
			log.Println("nftableHandler: error removing address:", err)
			return "", err
		} else {
			err := nft.Flush()
			if err != nil {
				log.Println("nftableHandler: failed to save changes")
			}
			return "deleted", nil
		}
	case "flush":
		nft.FlushSet(set)
		return "flushed", nil
	/*
	case "push":
		var exists = false
		exists, err = ipt.Exists("filter", chainName, "-s", ipvar, "-d", "0/0", "-j", targetChain)
		if err != nil {
			log.Println("iptableHandler: error checking if ip already exists", err)
			return "error checking if ip already exists in the chain", err
		} else {
			if exists {
				err = errors.New("ip already exists")
				log.Println("iptableHandler: ip already exists", err)
				return "ip already exists", err
			} else {
				err = ipt.Insert("filter", chainName, 1, "-s", ipvar, "-d", "0/0", "-j", targetChain)
				if err != nil {
					log.Println("iptableHandler: error pushing address", err)
					return "", err
				} else {
					return "pushed", nil
				}
			}
		}
	*/
	default:
		log.Println("iptableHandler: unknown task")
		return "", errors.New("unknown task")
	}
}

/*
func pushIPAddress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	log.Println("processing pushIPAddress", params["ipaddress"])

	ipType, err := checkIPAddressv4(params["ipaddress"])
	if err != nil {
		log.Println(params["ipaddress"], "is not a valid ip address")
		http.Error(w, "{\"error\":\"only valid ip addresses supported\"}", http.StatusBadRequest)
		return
	}

	status, err := iptableHandle(ipType, "push", params["ipaddress"])
	if err != nil {
		http.Error(w, "{\"error\":\""+err.Error()+"\"}", http.StatusBadRequest)
	} else {
		io.WriteString(w, "{\"success\":\""+status+"\"}\n")
	}
}
*/

func addIPAddress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	log.Println("processing addIPAddress", params["ipaddress"])

	_, err := checkIPAddressv4(params["ipaddress"])
	if err != nil {
		log.Println(params["ipaddress"], "is not a valid ip address")
		http.Error(w, "{\"error\":\"only valid ip addresses supported\"}", http.StatusBadRequest)
		return
	}

	status, err := nftableHandle("add", params["ipaddress"])
	if err != nil {
		http.Error(w, "{\"error\":\""+err.Error()+"\"}", http.StatusBadRequest)
	} else {
		io.WriteString(w, "{\"success\":\""+status+"\"}\n")
	}
}

func removeIPAddress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	log.Println("processing removeIPAddress", params["ipaddress"])

	_, err := checkIPAddressv4(params["ipaddress"])
	if err != nil {
		log.Println(params["ipaddress"], "is not a valid ip address")
		http.Error(w, "{\"error\":\"only valid ip addresses supported\"}", http.StatusBadRequest)
		return
	}

	status, err := nftableHandle("delete", params["ipaddress"])
	if err != nil {
		http.Error(w, "{\"error\":\""+err.Error()+"\"}", http.StatusBadRequest)
	} else {
		io.WriteString(w, "{\"success\":\""+status+"\"}\n")
	}
}

func flushSet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	log.Println("processing flushSet")
	var flushResult string

	_, err := nftableHandle("flush", "")
	if err != nil {
		flushResult = "ipv4" + err.Error() + ". "
	} else {
		flushResult = "ipv4 flushed. "
	}

	_, err = nftableHandle("flush", "")
	if err != nil {
		flushResult = flushResult + "ipv6" + err.Error() + ". "
	} else {
		flushResult = flushResult + "ipv6 flushed. "
	}

	io.WriteString(w, "{\"result\":\""+flushResult+"\"}\n")
}

func rHandleIPAddress(w http.ResponseWriter, r *http.Request) {
	log.Println("processing rHandleIPAddress", r.Method)
	var handleType string
	switch r.Method {
	case "DELETE":
		handleType = "delete"
	/*
	case "PUT":
		handleType = "push"
	*/
	case "POST":
		handleType = "add"
	}

	// parse body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("bodyErr ", err.Error())
		http.Error(w, "{\"error\":\"unable to read body\"}", http.StatusBadRequest)
		return
	}

	log.Println("body received ->", string(body))
	keyVal := pgparse.ParseBody(body)
	keyVal = pgparse.LowerKeys(keyVal)
	log.Println("body (lowercase):", keyVal)

	// check for required fields
	requiredfields := []string{"ipaddress"}
	_, err = pgparse.CheckFields(keyVal, requiredfields)

	if err != nil {
		log.Println("errors occured:", err)
		http.Error(w, "{\"error\":\""+err.Error()+"\"}", http.StatusBadRequest)
		return
	}

	_, err = checkIPAddressv4(keyVal["ipaddress"])
	if err != nil {
		log.Println(keyVal["ipaddress"], "is not a valid ip address")
		http.Error(w, "{\"error\":\"only valid ip addresses supported\"}", http.StatusBadRequest)
		return
	}

	status, err := nftableHandle(handleType, keyVal["ipaddress"])
	if err != nil {
		http.Error(w, "{\"error\":\""+err.Error()+"\"}", http.StatusBadRequest)
	} else {
		io.WriteString(w, "{\"success\":\""+status+"\"}\n")
	}
}
