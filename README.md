# DISCONTINUATION OF PROJECT #  
This project will no longer be maintained by Intel.  
Intel has ceased development and contributions including, but not limited to, maintenance, bug fixes, new releases, or updates, to this project.  
Intel no longer accepts patches to this project.  
 If you have an ongoing need to use this project, are interested in independently developing it, or would like to maintain patches for the open source software community, please create your own fork of this project.  
  
HID USI BPF tools
=================
This repository contains BPF tools for HID USI. Two programs are built
out of this repository: a client program (hid_usi_client), and a server
(hid_usi_server) containing a BPF kernel object.

Kernel config
-------------
Kernel to be used must contain the following BPF config:

    CONFIG_BPF_SYSCALL=y
    CONFIG_BPF_JIT=y
    CONFIG_BPF_JIT_DEFAULT_ON=y
    CONFIG_KALLSYMS_ALL=y
    CONFIG_DEBUG_INFO=y
    CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
    CONFIG_DEBUG_INFO_BTF=y
    CONFIG_PAHOLE_HAS_SPLIT_BTF=y
    CONFIG_DEBUG_INFO_BTF_MODULES=y
    CONFIG_GDB_SCRIPTS=y
    CONFIG_BPF_EVENTS=y

Building
--------
To build deps + BPF tools, enter src/ directory and:

    make KERNEL_SRC=<kernel-dir> deps
    make KERNEL_SRC=<kernel-dir> all

If everything passes correctly, output images should be available at
the source directory.

Kernel BPF program
------------------
Kernel BPF program is built out of hid_usi_server_kern.c, and it is
built-in to the hid_usi_server. The BPF program is automatically
started once the server is started.

Server program
--------------
Server program is called hid_usi_server and it will load the BPF program
to kernel, and create a D-BUS server over which it can be used to program
the pen parameters. Server source is at hid_usi_server.c. To launch the
server program, run

    hid_usi_server 0

This will attach the server to hidraw0 device and load the common BPF object.
Server will also create a D-BUS service over system bus for the client to
attach to.

Client program
--------------
Client program can be used to tell the server to program pen parameters.
Client source is at hid_usi_client.c. To launch the client program, simply
do:

    hid_usi_client

It will automatically connect to the server and will show the help text. E.g.
to dump current parameters, run:

    hid_usi_client --dump

Pen parameters can also be modified, e.g.

    hid_usi_client --color 3

... will change the pen color to 3.
