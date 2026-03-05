/* Linker script for sotOS shared objects (ET_DYN, PIC). */

PHDRS {
    text PT_LOAD FLAGS(5);    /* R+X */
    data PT_LOAD FLAGS(6);    /* R+W */
    dynamic PT_DYNAMIC;
}
SECTIONS {
    . = 0;

    .text     : { *(.text .text.*) } :text
    .rodata   : { *(.rodata .rodata.*) } :text

    . = ALIGN(4096);

    .dynsym   : { *(.dynsym) } :data
    .gnu.hash : { *(.gnu.hash) } :data
    .dynstr   : { *(.dynstr) } :data
    .rela.dyn : { *(.rela.dyn .rela.*) } :data
    .rela.plt : { *(.rela.plt) } :data

    .dynamic  : { *(.dynamic) } :data :dynamic

    .got      : { *(.got) } :data
    .got.plt  : { *(.got.plt) } :data
    .data     : { *(.data .data.*) } :data
    .bss      : { *(.bss .bss.*) *(COMMON) } :data

    /DISCARD/ : { *(.eh_frame) *(.note*) *(.comment) }
}
