/*
 * sotX Kernel Linker Script
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
        /* Static kernel binary -- `.got` is empty in practice but rust-lld
         * still emits a placeholder section. Folding it into `.data`
         * gives it a well-defined load address instead of colliding with
         * `.text` at 0xFFFF_FFFF_8000_0000. */
        *(.got .got.*)
        *(.got.plt .got.plt.*)

        /* Limine request sections — must be inside .data */
        KEEP(*(.requests_start_marker))
        KEEP(*(.requests))
        KEEP(*(.requests_end_marker))
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
