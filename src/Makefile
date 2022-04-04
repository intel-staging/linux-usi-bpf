BPFOBJS = hid_usi_server_kern.o
UOBJS = hid_usi_server.o hid_usi_client.o hid_parser.o
PROGS = hid_usi_server hid_usi_client

hid_usi_server_objs = hid_usi_server.o hid_parser.o
hid_usi_client_objs = hid_usi_client.o

INSTALL_DIR ?= .
ifndef KERNEL_SRC
$(error "KERNEL_SRC not defined. Aborted.")
endif
KERNEL_OBJ ?= $(KERNEL_SRC)
CLANG ?= clang
BPF_INC_FLAGS =
BPF_EXTRA_CFLAGS ?= -O2 -g -target bpf
CFLAGS = -Wall -O2 -Wmissing-prototypes -Wstrict-prototypes $(EXTRA_CFLAGS)
LDFLAGS_DBUS = $(shell pkg-config --libs dbus-glib-1)
LDFLAGS_GIO = $(shell pkg-config --libs gio-2.0)
BPFTOOL = $(KERNEL_OBJ)/bpftool

ifeq ($(COVERAGE),1)
	COVOPT=-fprofile-instr-generate -fcoverage-mapping
endif

ifneq ($(KERNEL_OBJ),$(KERNEL_SRC))
	ODIR=O=$(KERNEL_OBJ)
endif

LDLIBS = $(KERNEL_OBJ)/libbpf/libbpf.a \
	 -lelf -lz

hid_usi_server_libs = $(LDFLAGS_DBUS) $(LDFLAGS_GIO)
hid_usi_client_libs = $(LDFLAGS_DBUS) $(LDFLAGS_GIO)

BPF_INC = -I$(KERNEL_SRC)/arch/x86/include \
	  -I$(KERNEL_OBJ)/arch/x86/include/generated \
	  -I$(KERNEL_SRC)/include \
	  -I$(KERNEL_OBJ)/include \
	  -I$(KERNEL_SRC)/arch/x86/include/uapi \
	  -I$(KERNEL_OBJ)/arch/x86/include/generated/uapi \
	  -I$(KERNEL_SRC)/include/uapi \
	  -I$(KERNEL_OBJ)/include/generated/uapi \
	  -I$(KERNEL_SRC)/tools/testing/selftests \
	  -I$(KERNEL_SRC)/samples/bpf/libbpf/include \
	  -I$(KERNEL_SRC)/tools/lib \
	  -I$(KERNEL_OBJ)/samples/bpf \
	  -I$(KERNEL_OBJ)/libbpf/ \
	  -include $(KERNEL_SRC)/include/linux/kconfig.h \
	  -include $(KERNEL_SRC)/samples/bpf/asm_goto_workaround.h

U_INC = -I$(KERNEL_OBJ)/usr/include \
	-I$(KERNEL_SRC)/tools/include \
	-I$(KERNEL_SRC)/tools/lib/bpf \
	-I$(KERNEL_SRC)/tools/lib \
	-I$(KERNEL_SRC)/include/uapi \
	-I$(KERNEL_SRC)/tools/testing/selftests/bpf \
	-I$(KERNEL_OBJ)/samples/bpf/libbpf/include \
	-I$(KERNEL_OBJ)/include/ \
	-I/usr/include/dbus-1.0 \
	-I/usr/include/glib-2.0 \
	-I/usr/lib/x86_64-linux-gnu/dbus-1.0/include \
	-I/usr/lib/x86_64-linux-gnu/glib-2.0/include

GIT_COMMIT ?= $(shell git log -1 --pretty=format:"%H")

all: $(BPFOBJS) $(UOBJS) $(PROGS)

.PHONY: clean

$(BPFTOOL): deps

install: $(PROGS)
	cp $(PROGS) $(INSTALL_DIR)

deps:
	make -C $(KERNEL_SRC) $(ODIR) headers_install
	make -C $(KERNEL_SRC) $(ODIR) -C tools/bpf/bpftool

clean:
	rm -f $(BPFOBJS) $(UOBJS) $(PROGS) $(subst .o,.h,$(BPFOBJS))

clean_deps: clean
	make -C $(KERNEL_SRC) $(ODIR) -C tools/bpf/bpftool clean

$(BPFOBJS):  %.o:%.c
	$(CLANG) $(BPF_INC_FLAGS) $(BPF_INC) \
		-D__KERNEL__ -D__BPF_TRACING__ -D__TARGET_ARCH_x86 \
		-Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option \
		-fno-asynchronous-unwind-tables \
		-fno-stack-protector \
		$(BPF_EXTRA_CFLAGS) \
		-c $< -o $@
	$(BPFTOOL) gen skeleton $@ > $(subst .o,.h,$@)

$(UOBJS): %.o: %.c $(BPFOBJS)
	$(CC) -Wno-unused-variable $(U_INC) $(COVOPT) -DGIT_COMMIT=\"$(GIT_COMMIT)\" -c -o $@ $< $(CFLAGS)

$(PROGS): $(UOBJS)
	$(CC) -o $@ $($(@)_objs) $(CFLAGS) $(COVOPT) $(EXTRA_LDFLAGS) $(LDLIBS) $($(@)_libs)
