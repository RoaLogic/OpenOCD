# OpenOCD
OpenOCD clone for porting RoaLogic Debuggers

Build instruction:

to build roalogic OpenOCD, use the following sequence of commands:

./bootstrap
./configure [options]
make
sudo make install

optional to clean the directory:
make distclean

The 'configure' step generates the Makefiles required to build
OpenOCD, usually with one or more options provided to it. The first
'make' step will build OpenOCD and place the final executable in
'./src/'. The final (optional) step, ``make install'', places all of
the files in the required location.

To see the list of all the supported options, run
  ./configure --help

Interesting options:
--prefix=<install_dir>   	This option sets the installation directory
--enable-jtag_vpi		This option enables the vpi client for simulatie debugging

Run roalogic OpenOCD:

To be added (*.cfg to be created)

GDB connection over terminal

>set remotetimeout 30			Sets the command timeout to 30 seconds (for simulation)
>set arch riscv:rv32			Select the riscv RV32 architecture

Run from GDB terminal to connect:
>target extended remote:3333		Command to connect GDB with roalogic OpenOCD

After this all standard GDB commands can be executed
use help for all commands

Telnet connection over terminal
>telnet localhost 4444
use help for all commands or look at: openocd.org/doc/html/General-Commands.html
