ENTRY(_start)
PHDRS {
    text PT_LOAD FLAGS(5);   /* R+X */
    data PT_LOAD FLAGS(6);   /* R+W */
    tls  PT_TLS  FLAGS(4);   /* R (TLS template) */
}
SECTIONS {
    . = 0x200000;

    .text   : { *(.text .text.*) } :text
    .rodata : { *(.rodata .rodata.*) } :text

    /*
     * NetBSD link sets — the rump kernel auto-registers components, sysctls,
     * modules, and event counters by stuffing function/struct pointers into
     * sections named "link_set_<NAME>". Modern GNU ld auto-generates the
     * __start_/__stop_ symbols for any C-identifier-named output section,
     * but only if every contributing input section ends up in the output.
     * Drop them all into .rodata via wildcard so they survive the link.
     */
    /*
     * Each link_set_<name> needs its own output section so we can emit the
     * encapsulation symbols (__start_/__stop_) ourselves with HIDDEN
     * visibility — lld refuses to auto-generate hidden start/stop symbols.
     */
    link_set_bufq_strats : {
        PROVIDE_HIDDEN(__start_link_set_bufq_strats = .);
        KEEP(*(link_set_bufq_strats));
        PROVIDE_HIDDEN(__stop_link_set_bufq_strats = .);
    } :text
    link_set_dkwedge_methods : {
        PROVIDE_HIDDEN(__start_link_set_dkwedge_methods = .);
        KEEP(*(link_set_dkwedge_methods));
        PROVIDE_HIDDEN(__stop_link_set_dkwedge_methods = .);
    } :text
    link_set_evcnts : {
        PROVIDE_HIDDEN(__start_link_set_evcnts = .);
        KEEP(*(link_set_evcnts));
        PROVIDE_HIDDEN(__stop_link_set_evcnts = .);
    } :text
    link_set_modules : {
        PROVIDE_HIDDEN(__start_link_set_modules = .);
        KEEP(*(link_set_modules));
        PROVIDE_HIDDEN(__stop_link_set_modules = .);
    } :text
    link_set_prop_linkpools : {
        PROVIDE_HIDDEN(__start_link_set_prop_linkpools = .);
        KEEP(*(link_set_prop_linkpools));
        PROVIDE_HIDDEN(__stop_link_set_prop_linkpools = .);
    } :text
    link_set_rump_components : {
        PROVIDE_HIDDEN(__start_link_set_rump_components = .);
        KEEP(*(link_set_rump_components));
        PROVIDE_HIDDEN(__stop_link_set_rump_components = .);
    } :text
    link_set_sysctl_funcs : {
        PROVIDE_HIDDEN(__start_link_set_sysctl_funcs = .);
        KEEP(*(link_set_sysctl_funcs));
        PROVIDE_HIDDEN(__stop_link_set_sysctl_funcs = .);
    } :text
    /* Catch-all for any link_set_* not explicitly enumerated above. */
    .link_sets_misc : {
        KEEP(*(link_set_*));
    } :text

    . = ALIGN(4096);
    .data   : { *(.data .data.*) } :data

    /*
     * TLS template: __thread variables in the rump kernel code live
     * here. The initial-exec model used by -fno-pic + __thread emits
     * `fs:offset` loads; the runtime must copy this template into a
     * per-thread TLS block pointed to by FS_BASE. We keep it in its
     * own PT_TLS segment so ld can build the p_filesz / p_memsz the
     * dynamic loader (and our trampoline) need. Our init's
     * rump_worker allocates a TLS block and copies this template in
     * before calling rump_init.
     */
    .tdata  : ALIGN(16) { *(.tdata .tdata.*) } :data :tls
    .tbss   : ALIGN(16) { *(.tbss .tbss.* .gnu.linkonce.tb.*) } :data :tls

    .bss    : { *(.bss .bss.*) *(COMMON) } :data

    /DISCARD/ : { *(.eh_frame) *(.note*) *(.comment) }
}
