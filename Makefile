# The development version of clang is distributed as the 'clang' binary,
# while stable/released versions have a version number attached.
# Pin the default clang to a stable version.
CLANG ?= clang-14
STRIP ?= llvm-strip-14
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

# Obtain an absolute path to the directory of the Makefile.
# Assume the Makefile is in the root of the repository.
REPODIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
UIDGID := $(shell stat -c '%u:%g' ${REPODIR})

# Prefer podman if installed, otherwise use docker.
# Note: Setting the var at runtime will always override.
CONTAINER_ENGINE ?= $(if $(shell command -v podman), podman, docker)
CONTAINER_RUN_ARGS ?= $(if $(filter ${CONTAINER_ENGINE}, podman),, --user "${UIDGID}")

IMAGE := quay.io/cilium/ebpf-builder
VERSION := 1648566014

# clang <8 doesn't tag relocs properly (STT_NOTYPE)
# clang 9 is the first version emitting BTF
# TARGETS := \
# 	testdata/loader-clang-7 \
# 	testdata/loader-clang-9 \
# 	testdata/loader-$(CLANG) \
# 	testdata/btf_map_init \
# 	testdata/invalid_map \
# 	testdata/raw_tracepoint \
# 	testdata/invalid_map_static \
# 	testdata/invalid_btf_map_init \
# 	testdata/strings \
# 	testdata/freplace \
# 	testdata/iproute2_map_compat \
# 	testdata/map_spin_lock \
# 	testdata/subprog_reloc \
# 	testdata/fwd_decl \
# 	internal/btf/testdata/relocs \
# 	internal/btf/testdata/relocs_read \
# 	internal/btf/testdata/relocs_read_tgt

.PHONY: #all clean container-all container-shell generate

.DEFAULT_TARGET = container-all

# Build all ELF binaries using a containerized LLVM toolchain.
container-all:
	${CONTAINER_ENGINE} run --rm ${CONTAINER_RUN_ARGS} \
		-v "${REPODIR}":/ebpf -w /ebpf --env MAKEFLAGS \
		--env CFLAGS="-fdebug-prefix-map=/ebpf=." \
		--env HOME="/tmp" \
		"${IMAGE}:${VERSION}" \
		$(MAKE) all

# (debug) Drop the user into a shell inside the container as root.
container-shell:
	${CONTAINER_ENGINE} run --rm -ti \
		-v "${REPODIR}":/ebpf -w /ebpf \
		"${IMAGE}:${VERSION}"

clean:
	-$(RM) testdata/*.elf
	-$(RM) internal/btf/testdata/*.elf

format:
	find . -type f -name "*.c" | xargs clang-format -i

all: format $(addsuffix -el.elf,$(TARGETS)) $(addsuffix -eb.elf,$(TARGETS)) generate
	ln -srf testdata/loader-$(CLANG)-el.elf testdata/loader-el.elf
	ln -srf testdata/loader-$(CLANG)-eb.elf testdata/loader-eb.elf

# $BPF_CLANG is used in go:generate invocations.
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./

%-el.elf: %.c
	$(CLANG) $(CFLAGS) -target bpfel -c $< -o $@
	$(STRIP) -g $@

%-eb.elf : %.c
	$(CLANG) $(CFLAGS) -target bpfeb -c $< -o $@
	$(STRIP) -g $@

	
run: .PHONY
	go get github.com/cilium/ebpf/cmd/bpf2go@latest
	go generate ./
	go build
	docker kill server || true && docker rm server || true
	docker run --name server -d -p 8080:80 nginx
	sudo ./go-ebpf-proxy-example 169.1.1.1 $(shell docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' server)