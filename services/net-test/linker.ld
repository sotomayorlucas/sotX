ENTRY(_start)
PHDRS {
    text PT_LOAD FLAGS(5);   /* R+X */
    data PT_LOAD FLAGS(6);   /* R+W */
}
SECTIONS {
    . = 0x6000000;
    .text   : { *(.text .text.*) } :text
    .rodata : { *(.rodata .rodata.*) } :text
    . = ALIGN(4096);
    .data   : { *(.data .data.*) } :data
    .bss    : { *(.bss .bss.*) *(COMMON) } :data
    /DISCARD/ : { *(.eh_frame) *(.note*) }
}
