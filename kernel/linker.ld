/*
 * sotOS Kernel Linker Script
 * Higher-half kernel at 0xFFFFFFFF80000000 using Limine boot protocol.
 */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(kmain)

PHDRS
{
    text   PT_LOAD;
    rodata PT_LOAD;
    data   PT_LOAD;
}

SECTIONS
{
    . = 0xFFFFFFFF80000000;

    .text : {
        *(.text .text.*)
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .data : {
        *(.data .data.*)

        /* Limine request sections — must be inside .data */
        KEEP(*(.requests_start_marker))
        KEEP(*(.requests))
        KEEP(*(.requests_end_marker))
    } :data

    .user_init : {
        KEEP(*(.user_init))
    } :data

    .user_recv : {
        KEEP(*(.user_recv))
    } :data

    .user_kb : {
        KEEP(*(.user_kb))
    } :data

    .user_async_tx : {
        KEEP(*(.user_async_tx))
    } :data

    .user_async_rx : {
        KEEP(*(.user_async_rx))
    } :data

    .user_child : {
        KEEP(*(.user_child))
    } :data

    .user_shm_tx : {
        KEEP(*(.user_shm_tx))
    } :data

    .user_shm_rx : {
        KEEP(*(.user_shm_rx))
    } :data

    .user_serial : {
        KEEP(*(.user_serial))
    } :data

    .user_vmm : {
        KEEP(*(.user_vmm))
    } :data

    .user_fault_test : {
        KEEP(*(.user_fault_test))
    } :data

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
    }
}
