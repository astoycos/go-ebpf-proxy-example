//go:build linux
// +build linux

package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"strings"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf cgroup_connect4.c -- -I./headers

const bpfFSPath = "/sys/fs/bpf"

func main() {
	var err error
	// Name of the kernel function we're tracing
	fn := "count_sock4_connect"

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	pinPath := path.Join(bpfFSPath, fn)
	if err := os.MkdirAll(pinPath, os.ModePerm); err != nil {
		log.Fatalf("failed to create bpf fs subpath: %+v", err)
	}

	log.Printf("Pin Path is %s", pinPath)

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, &cebpf.CollectionOptions{
		Maps: cebpf.MapOptions{
			// Pin the map to the BPF filesystem and configure the
			// library to automatically re-write it in the BPF
			// program so it can be re-used if it already exists or
			// create it if not
			PinPath: pinPath,
		},
	}); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	info, err := objs.bpfMaps.V4SvcMap.Info()
	if err != nil {
		log.Fatalf("Cannot get map info: %v", err)
	}
	log.Printf("Svc Map Info: %+v", info)

	info, err = objs.bpfMaps.V4BackendMap.Info()
	if err != nil {
		log.Fatalf("Cannot get map info: %v", err)
	}
	log.Printf("Backend Map Info: %+v", info)

	// Add a fake service with one backend
	fakeServiceValue := Service4Value{
		BackendID: 0,
		Count:     1,
	}

	fakeServiceValue2 := fakeServiceValue
	fakeServiceValue2.Count = 0
	fakeServiceValue2.BackendID = 500

	fakeVIP := net.ParseIP(os.Args[1])
	port := [2]byte{}

	binary.BigEndian.PutUint16(port[:], 80)

	fakeServiceKey := Service4Key{
		Port:        port,
		BackendSlot: 0,
	}

	fakeServiceKey2 := fakeServiceKey
	fakeServiceKey2.BackendSlot = 1

	copy(fakeServiceKey.Address[:], fakeVIP.To4())
	copy(fakeServiceKey2.Address[:], fakeVIP.To4())

	fakeBackendIP := net.ParseIP(os.Args[2])

	// Add a fake backend
	fakeBackend := Backend4Value{
		Port:  port,
		Proto: 6, // TCP
	}

	copy(fakeBackend.Address[:], fakeBackendIP.To4())

	// I picked a random key here
	fakeBackendKey := Backend4Key{
		ID: 500,
	}

	log.Printf("Loading with service %+v servicekey %+v, backend %+v backendKey %+v", fakeServiceValue,
		fakeServiceKey, fakeBackend, fakeBackendKey)

	if _, err := objs.V4SvcMap.BatchUpdate([]Service4Key{fakeServiceKey, fakeServiceKey2}, []Service4Value{fakeServiceValue, fakeServiceValue2}, &cebpf.BatchOptions{}); err != nil {
		log.Fatalf("Failed Loading a fake service: %v", err)
	}

	if err := objs.V4BackendMap.Put(fakeBackendKey.ID, fakeBackend); err != nil {
		log.Fatalf("Failed Loading a fake backend: %v", err)
	}

	// Get the first-mounted cgroupv2 path.
	cgroupPath, err := detectRootCgroupPath()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Cgroup Path is %s", cgroupPath)

	// Link the proxy program to the default cgroup.
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  cebpf.AttachCGroupInet4Connect,
		Program: objs.Sock4Connect,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	// log.Printf("returned service value: %+v", fakeServiceOut)
	log.Printf("Proxing for VIP %s to backend %s at Port 80", os.Args[1], os.Args[2])

	log.Printf("Curling VIP %s:80 from host", os.Args[1])
	resp, err := http.Get("http://169.1.1.1")
	if err != nil {
		log.Printf("Curl to VIP failed: %v", err)
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	log.Printf("Response: %s", string(body))

}

// detectCgroupPath returns the first-found mount point of type cgroup2
// and stores it in the cgroupPath global variable.
func detectRootCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 not mounted")
}
