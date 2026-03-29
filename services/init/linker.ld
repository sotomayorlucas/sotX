ENTRY(_start)
PHDRS {
    text PT_LOAD FLAGS(5);   /* R+X */
    data PT_LOAD FLAGS(6);   /* R+W */
}
SECTIONS {
    . = 0x68000000;
    .text   : { *(.text .text.*) } :text
    .rodata : { *(.rodata .rodata.*) } :text
    /* LKL kernel uses __start_notes/__stop_notes for ksysfs */
    notes : { *(.notes) } :text
    .init.data : { *(.init.data) } :text
    .initcall : {
        __initcall_start = .;
        *(.initcall*)
        __initcall_end = .;
    } :text
    . = ALIGN(4096);
    .data   : { *(.data .data.*) } :data
    .bss    : { *(.bss .bss.*) *(COMMON) } :data
    /DISCARD/ : { *(.eh_frame) }
}
