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
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"

	"github.com/google/nftables"
	"github.com/gorilla/mux"
)

var listen string
var logFile string
var targetTable string

func init() {
	flag.StringVar(&targetTable, "table", "mytable", "target table")
	flag.StringVar(&listen, "listen", "[::1]:8082", "address and port to listen on")
}

func main() {
	flag.Parse()

	log.Print("** Starting nftables-API")
	log.Print("** Choose to be optimistic, it feels better.")
	log.Print("** Licensed under GPLv2. See LICENSE for details.")
	log.Print("** Listening on ", listen)

	router := mux.NewRouter()
	router.HandleFunc("/set/{set}/{value}", handleSetRoute).Methods("DELETE", "POST", "PUT")
	http.ListenAndServe(listen, router)
}

func nftablesGetSet(nft *nftables.Conn, targetSetF string) (*nftables.Set, error) {
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

func SetContainsElement(nft *nftables.Conn, set *nftables.Set, element []nftables.SetElement) (bool, error) {

	existingElements, err := nft.GetSetElements(set)
	if err != nil {
		return false, err
	}

	for _, existingElement := range existingElements {
		if bytes.Equal(existingElement.Key, element[0].Key) {
			return true, nil
		}
	}

	return false, nil
}

func nftablesPutSetElement(nft *nftables.Conn, set *nftables.Set, element []nftables.SetElement) (string, error) {

	contains, err := SetContainsElement(nft, set, element)
	if err != nil {
		return "error", err
	}
	if contains {
		log.Println("address already in set")
		return "already", nil
	} else {
		err := nft.SetAddElements(set, element)
		if err != nil {
			log.Println("error adding address: %w", err)
			return "error", err
		}
	}
	return "added", nil
}

func nftablesDeleteSetElement(nft *nftables.Conn, set *nftables.Set, element []nftables.SetElement) (string, error) {

	contains, err := SetContainsElement(nft, set, element)
	if err != nil {
		return "error", err
	}
	if contains {
		log.Println("deleting address from set")
		err = nft.SetDeleteElements(set, element)
		if err != nil {
			log.Println("error removing address: %w", err)
			return "error", err
		}
		return "deleted", nil
	} else {
		return "not present", nil
	}
}

func nftablesHandle(task string, setprefix string, ipvar string) (string, error) {
	log.Println("nftablesHandle:", task, setprefix, ipvar)

	// Go connect for nftables
	nft, err := nftables.New()
	if err != nil {
		log.Println("nftablesHandle:", err)
		return "", err
	}
	

	var setname string
	var address net.IP
	var addressFamily string
	var element []nftables.SetElement

	if task == "flush" {
		setname = setprefix
	} else {
		address, addressFamily = ParseIPAddress(ipvar)
		setname = AddressFamilyToSetName(setprefix, addressFamily)

		element = []nftables.SetElement {
			{
				Key: []byte(address),
			},
		}

	}

	set, err := nftablesGetSet(nft, setname)
	if err != nil {
		log.Println("nftablesHandler: failed to initialize NFTables:", err)
		return "", err
	}


	var status string
	switch task {

		case "add":
			log.Println("nftablesHandler: adding address")
			status, err = nftablesPutSetElement(nft, set, element)

		case "delete":
			log.Println("nftablesHandler: deleting address")
			status, err = nftablesDeleteSetElement(nft, set, element)

		case "flush":
			nft.FlushSet(set)
			return "requested", nil

		default:
			log.Println("iptableHandler: unknown task")
			return "", errors.New("unknown task")
		}

	if err != nil {
		log.Println("nftablesHandler: error in task %w: %w", task, err)
		return status, err
	}

	ferr := nft.Flush()
	if ferr != nil {
		log.Println("nftablesHandler: failed to save changes: %w", ferr)
		return "", ferr
	}
	return status, nil

}

func handleSetRoute(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	method := r.Method
	set := params["set"]
	value := params["value"]
	log.Println("processing request for set %w, value %w", set, value)

	if method == "POST" {
		if value == "flush" {
			var flushResult string
			status, err := nftablesHandle("flush", set, "")
			if err == nil {
				flushResult = status
				io.WriteString(w, "{\"result\":\""+flushResult+"\"}\n")
			} else {
				flushResult = status + " " + err.Error()
				http.Error(w, "{\"error\":\"" + flushResult + "\"}", http.StatusBadRequest)
			}
		} else {
			http.Error(w, "{\"error\":\"only flush is supported for POST\"}", http.StatusBadRequest)
		}
	} else {
		_, err := GetIPAddressFamily(value)
		if err != nil {
			log.Println(value, "is not a valid IP address")
			http.Error(w, "{\"error\":\"only flush or IP addresses are supported\"}", http.StatusBadRequest)
			return
		}

		var task string
		switch method {
			case "PUT":
				task = "add"
			
			case "DELETE":
				task = "delete"

			default:
				log.Println("illegal method, this should not happen here")
				return
		}

		status, err := nftablesHandle(task, set, value)
		if err != nil {
			http.Error(w, "{\"error\":\""+err.Error()+"\"}", http.StatusBadRequest)
		} else {
			io.WriteString(w, "{\"success\":\""+status+"\"}\n")
		}
	}
}
