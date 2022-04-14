.. SPDX-License-Identifier: GPL-2.0

===========================
HYGON Secure Virtualization
===========================

Secure Virtualization (CSV) is a key virtualization feature on Hygon processors.

CSV feature integrates secure processor, memory encryption and memory isolation
to provide the ability to protect guest's private data. The CSV guest's context
like CPU registers, control block and nested page table is accessed only by the
guest itself and the secure processor. Neither other guests nor the host can
tamper with the guest's context.

The secure processor is a separate processor inside Hygon hardware. The firmware
running inside the secure processor performs activities in a secure way, such as
OVMF encryption, VM launch, secure memory management and nested page table
management etc. For more information, please see CSV spec from Hygon.

A CSV guest is running in the memory that is encrypted with a dedicated encrypt
key which is set by the secure processor. And CSV guest's memory encrypt key is
unique from the others. A low latency crypto engine resides on Hygon hardware
to minimize the negative effect on memory bandwidth. In CSV guest, a guest private
page will be automatically decrypted when read from memory and encrypted when
written to memory.

CSV feature provides an enhancement technology named memory isolation to improve
the security. A dedicated memory isolation hardware is built in Hygon hardware.
Only the secure processor has privilege to configure the isolation hardware. At
the BIOS stage, host will reserve several memory regions as secure which are
protected by the isolation hardware. The secure processor allocates the reserved
secure memory for CSV guest and mark the memory as dedicated for the current CSV
guest. Any memory access (read or write) to CSV guest's private memory outside
the guest will be blocked by isolation hardware.

A CSV guest may declare some memory regions as shared to share data with the host.
When a page is set as shared, read/write on the page will bypass the isolation
hardware and the guest's shared memory can be accessed by the host. A method named
CSV secure call command is designed and CSV guest sends the secure call command
to the secure processor to change private memory to shared memory. In the method,
2 dedicated pages are reserved at early stage of the guest. Any read/write on the
dedicated pages will trigger nested page fault. When NPF happens, the host helps
to issue an external command to the secure processor but cannot tamper with the
data in the guest's private memory. Then the secure processor checks the fault
address and handles the command if the address is exactly the dedicated pages.

Support for CSV can be determined through the CPUID instruction. The CPUID function
0x8000001f reports information to CSV::

	0x8000001f[eax]:
		Bit[30]	  indicates support for CSV

If CSV is support, MSR 0xc0010131 can be used to determine if CSV is active::

	0xc0010131:
		Bit[30]	  0 = CSV is not active
			  1 = CSV is active
