package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

type json_map map[string]interface{}

var DECODE_TYPES = map[string]bool{
	"proctitle": true,
	"arch":      true,
}

func trimRightFromString(psrc *string, pattern string) (trimmed string) {
	idx := strings.Index(*psrc, pattern)
	trimmed = string(*psrc)
	if idx >= 0 {
		trimmed = (*psrc)[:idx]
	}
	return trimmed
}

func trimQuotesFromString(psrc *string) (trimmed string) {
	trimmed = string(*psrc)
	if len(trimmed) > 1 && trimmed[0] == '"' {
		trimmed = trimmed[1:]
	}

	if len(trimmed) > 1 && trimmed[len(trimmed)-1] == '"' {
		trimmed = trimmed[:len(trimmed)-1]
	}
	return trimmed

}
func process_group(grp *AuditMessageGroup) (tmp json_map, err error) {
	tmp = json_map{}
	tmp["timestamp"] = trimRightFromString(&grp.AuditTime, ".")
	args := json_map{} // execve args
	paths_list := []string{}
	paths_map := json_map{}
	tmp["hostname"], _ = os.Hostname()
	for i := 0; i < len(grp.Msgs); i++ {
		msg, _ := grp.Msgs[i]
		if AUDITD_EVENT_TYPES[msg.Type] == "execve" {
			parse_kvs(&msg.Data, &args)
			tmp["args"] = args
		} else {
			parse_kvs(&msg.Data, &tmp)
		}

		if AUDITD_EVENT_TYPES[msg.Type] == "syscall" {
			for i := 0; i < 4; i++ {
				delete(tmp, fmt.Sprintf("a%d", i))
			}
			if session, ok := (tmp["ses"]).(string); ok {
				tmp["session"] = session
				delete(tmp, "ses")
			}
		}

		if AUDITD_EVENT_TYPES[msg.Type] == "path" {
			tmp_kvs := json_map{}
			parse_kvs(&msg.Data, &tmp_kvs)
			paths_list = append(paths_list, tmp_kvs["name"].(string))
			paths_map[tmp_kvs["item"].(string)] = tmp_kvs
		}
	}

	// Set paths, paths_info if any path messages were processed
	if len(paths_map) > 0 {
		tmp["paths"] = paths_list
		tmp["paths_info"] = paths_map
	}
	set_username(&tmp, &grp.UidMap)
	set_syscall_type(&tmp, &grp.Syscall)
	return tmp, err
}

func parse_kvs(blob *string, pkvs *json_map) (err error) {
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
			kvs[k] = trimQuotesFromString(&v)
		}
		err = nil
	}
	return err
}

func set_username(pkvs *json_map, puidmap *map[string]string) (err error) {
	tmp := *pkvs
	uidmap := *puidmap
	var ok bool
	var user string
	var auid string
	if auid, ok = tmp["auid"].(string); ok {
		user, ok = uidmap[auid]
	}
	if !ok {
		user = ""
	}
	tmp["user"] = user
	return err
}

func set_syscall_type(pkvs *json_map, psyscall_id *string) (err error) {
	tmp := *pkvs
	syscall_id := *psyscall_id
	var arch string
	var ok bool
	if arch, ok = tmp["arch_name"].(string); ok {
		tmp["type"] = SYSCALLS[arch][syscall_id]
	}
	if !ok {
		tmp["type"] = "UNKNOWN"
	}
	return err
}
func map_arch(data *string, pkvs *json_map) (err error) {
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
