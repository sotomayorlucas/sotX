ENTRY(_start)
PHDRS {
    text PT_LOAD FLAGS(5);   /* R+X */
    data PT_LOAD FLAGS(6);   /* R+W */
}
SECTIONS {
    . = 0x10000000;
    .text       : { *(.text .text.*) } :text
    .rodata     : { *(.rodata .rodata.*) } :text
    .notes      : { *(.notes) } :text
    . = ALIGN(4096);
    .init.data  : { *(.init.data) } :data
    .init_array : {
        __init_array_start = .;
        *(.init_array .init_array.*)
        __init_array_end = .;
    } :data
    .data       : { *(.data .data.*) } :data
    .got        : { *(.got .got.*) } :data
    .got.plt    : { *(.got.plt) } :data
    .bss        : { *(.bss .bss.*) *(COMMON) } :data
    /DISCARD/   : { *(.eh_frame) *(.note.gnu*) *(.note.GNU*) *(.comment)
                    *(.fini_array) *(.fini_array.*) }
}
