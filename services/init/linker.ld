ENTRY(_start)
PHDRS {
    text PT_LOAD FLAGS(5);   /* R+X */
    data PT_LOAD FLAGS(6);   /* R+W */
    tls  PT_TLS  FLAGS(4);   /* TLS template (R only) — required because
                                  liblkl-in.o contains STT_TLS symbols. */
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
    /* TLS sections — live inside the data PT_LOAD on disk, but are ALSO
     * referenced by PT_TLS so the linker validates STT_TLS symbols. sotOS
     * does not implement POSIX per-thread TLS at runtime; the LKL paths
     * that actually touch these globals (thread-local in posix-host.c)
     * are never executed because host_ops.c supersedes them. */
    .tdata  : { *(.tdata .tdata.*) } :data :tls
    .tbss   : { *(.tbss .tbss.*) *(.tcommon) } :data :tls
    .data   : { *(.data .data.*) } :data
    .bss    : { *(.bss .bss.*) *(COMMON) } :data
    /DISCARD/ : { *(.eh_frame) }
}
