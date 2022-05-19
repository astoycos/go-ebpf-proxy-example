/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

// Service4Value must match 'struct lb4_service_v2' in "bpf/lib/common.h".
type Service4Value struct {
	BackendID uint32
	Count     uint16
	RevNat    uint16
	Flags     uint8
	Flags2    uint8
	Pad       pad2uint8
}

// Service4Key must match 'struct lb4_key' in "bpf/lib/common.h".
type Service4Key struct {
	Address     IPv4
	Port        Port
	BackendSlot uint16
	// Proto       uint8     `align:"proto"`
	// Scope       uint8     `align:"scope"`
	// Pad uint16 `align:"pad"`
}

// Backend4Value must match 'struct lb4_backend' in "bpf/lib/common.h".
type Backend4Value struct {
	Address IPv4
	Port    Port
	Proto   U8proto
	Flags   uint8
}

type pad2uint8 [2]uint8

type IPv4 [4]byte
type Port [2]byte

type U8proto uint8

type Backend4Key struct {
	ID uint32
}
