package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

var DECODE_TYPES = map[string]bool{
	"proctitle": true,
	"arch":      true,
}

func process_group(grp *AuditMessageGroup) (tmp map[string]interface{}, err error) {
	//var flat_events []*AuditMessage
	tmp = map[string]interface{}{}
	tmp["timestamp"] = grp.AuditTime
	//syscall, _ := strconv.Atoi(grp.Syscall)
	tmp["syscall_id"] = grp.Syscall
	for i := 0; i < len(grp.Msgs); i++ {
		msg := grp.Msgs[i]
		parse_kvs(&msg.Data, &tmp)
		//flat_events = append(flat_events, msg)
	}
	// Map auid to username
	if auid, ok := tmp["auid"]; ok {
		auid := fmt.Sprintf("%s", auid)
		if user, ok := grp.UidMap[auid]; ok {
			tmp["user"] = user
		}
	}
	arch := fmt.Sprintf("%s", tmp["arch_name"])
	tmp["type"] = SYSCALLS[arch][grp.Syscall]
	return tmp, err
}

func parse_kvs(blob *string, pkvs *map[string]interface{}) (err error) {
	kvs := *pkvs
	kvs_unparsed := strings.Split(*blob, " ")
	for i := 0; i < len(kvs_unparsed); i++ {
		split := strings.Split(kvs_unparsed[i], "=")
		if len(split) == 2 {
			k := split[0]
			v := split[1]
			if _, ok := DECODE_TYPES[k]; ok {
				if k == "arch" {
					map_arch(&v, pkvs)
				} else {
					v, _ = decode_hex_string(&v)
				}
			}
			kvs[k] = strings.ReplaceAll(v, "\"", "")
		}
		err = nil
	}
	return err
}

func map_arch(data *string, pkvs *map[string]interface{}) (err error) {
	arch, _ := decode_hex_int(data)
	kvs := *pkvs
	bits := "64"
	endianness := "little"
	if !((ARCH["64bit"])&arch != 0) {
		bits = "32"
	} else {
		arch ^= ARCH["64bit"]
	}
	kvs["bits"] = bits

	if !((ARCH["little_endian"])&arch != 0) {
		endianness = "big"
	} else {
		arch = arch ^ ARCH["little_endian"]
	}
	kvs["endianness"] = endianness

	if (ARCH["convention_mips64_n32"])&arch != 0 {
		arch = arch ^ ARCH["convention_mips64_n32"]
	}

	if name, ok := MACHINES[arch]; ok {
		kvs["arch_name"] = name
	} else {
		kvs["arch_name"] = fmt.Sprintf("Unrecognized Archietecture: %d", arch)
	}
	err = nil
	return err
}

func decode_hex_string(blob *string) (decoded string, err error) {
	/* Some values are hex-encoded if there are potentally non-ascii bytes  or spaces in the string
	   such as IP addresses and proctitles

		 This function helps those things become human readable
	*/
	bstring, _ := hex.DecodeString(*blob)
	decoded = string(bytes.ReplaceAll(bstring, []byte("\x00"), []byte(" ")))
	err = nil
	return decoded, err
}

func decode_hex_int(blob *string) (decoded int, err error) {
	/* Some values are hex-encoded if there are potentally non-ascii bytes  or spaces in the string
	   such as IP addresses and proctitles

		 This function helps those things become human readable
	*/
	bstring, _ := hex.DecodeString(*blob)
	var buint64 [8]byte
	copy(buint64[8-len(bstring):], bstring)
	decoded = int(binary.BigEndian.Uint64(buint64[:]))
	err = nil
	return decoded, err
}
