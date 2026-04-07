//! Linux-to-BSD errno translation, ported from FreeBSD sys/compat/linux/linux_errno.inc.
//!
//! FreeBSD source: `sys/compat/linux/linux_errno.inc` (BSD-2-Clause, Soren Schmidt)
//!
//! Linux syscalls return negative errno on failure; BSD uses positive errno.
//! The two numbering schemes diverge significantly above errno 34.

// ---------------------------------------------------------------------------
// Linux errno constants (include/uapi/asm-generic/errno-base.h + errno.h)
// ---------------------------------------------------------------------------

pub const LINUX_EPERM: i32 = 1;
pub const LINUX_ENOENT: i32 = 2;
pub const LINUX_ESRCH: i32 = 3;
pub const LINUX_EINTR: i32 = 4;
pub const LINUX_EIO: i32 = 5;
pub const LINUX_ENXIO: i32 = 6;
pub const LINUX_E2BIG: i32 = 7;
pub const LINUX_ENOEXEC: i32 = 8;
pub const LINUX_EBADF: i32 = 9;
pub const LINUX_ECHILD: i32 = 10;
pub const LINUX_EAGAIN: i32 = 11;
pub const LINUX_ENOMEM: i32 = 12;
pub const LINUX_EACCES: i32 = 13;
pub const LINUX_EFAULT: i32 = 14;
pub const LINUX_ENOTBLK: i32 = 15;
pub const LINUX_EBUSY: i32 = 16;
pub const LINUX_EEXIST: i32 = 17;
pub const LINUX_EXDEV: i32 = 18;
pub const LINUX_ENODEV: i32 = 19;
pub const LINUX_ENOTDIR: i32 = 20;
pub const LINUX_EISDIR: i32 = 21;
pub const LINUX_EINVAL: i32 = 22;
pub const LINUX_ENFILE: i32 = 23;
pub const LINUX_EMFILE: i32 = 24;
pub const LINUX_ENOTTY: i32 = 25;
pub const LINUX_ETXTBSY: i32 = 26;
pub const LINUX_EFBIG: i32 = 27;
pub const LINUX_ENOSPC: i32 = 28;
pub const LINUX_ESPIPE: i32 = 29;
pub const LINUX_EROFS: i32 = 30;
pub const LINUX_EMLINK: i32 = 31;
pub const LINUX_EPIPE: i32 = 32;
pub const LINUX_EDOM: i32 = 33;
pub const LINUX_ERANGE: i32 = 34;
pub const LINUX_EDEADLK: i32 = 35;
pub const LINUX_ENAMETOOLONG: i32 = 36;
pub const LINUX_ENOLCK: i32 = 37;
pub const LINUX_ENOSYS: i32 = 38;
pub const LINUX_ENOTEMPTY: i32 = 39;
pub const LINUX_ELOOP: i32 = 40;
pub const LINUX_ENOMSG: i32 = 42;
pub const LINUX_EIDRM: i32 = 43;
pub const LINUX_ECHRNG: i32 = 44;
pub const LINUX_EL2NSYNC: i32 = 45;
pub const LINUX_EL3HLT: i32 = 46;
pub const LINUX_EL3RST: i32 = 47;
pub const LINUX_ELNRNG: i32 = 48;
pub const LINUX_EUNATCH: i32 = 49;
pub const LINUX_ENOCSI: i32 = 50;
pub const LINUX_EL2HLT: i32 = 51;
pub const LINUX_EBADE: i32 = 52;
pub const LINUX_EBADR: i32 = 53;
pub const LINUX_EXFULL: i32 = 54;
pub const LINUX_ENOANO: i32 = 55;
pub const LINUX_EBADRQC: i32 = 56;
pub const LINUX_EBADSLT: i32 = 57;
pub const LINUX_EBFONT: i32 = 59;
pub const LINUX_ENOSTR: i32 = 60;
pub const LINUX_ENODATA: i32 = 61;
pub const LINUX_ENOTIME: i32 = 62;
pub const LINUX_ENOSR: i32 = 63;
pub const LINUX_ENONET: i32 = 64;
pub const LINUX_ENOPKG: i32 = 65;
pub const LINUX_EREMOTE: i32 = 66;
pub const LINUX_ENOLINK: i32 = 67;
pub const LINUX_EADV: i32 = 68;
pub const LINUX_ESRMNT: i32 = 69;
pub const LINUX_ECOMM: i32 = 70;
pub const LINUX_EPROTO: i32 = 71;
pub const LINUX_EMULTIHOP: i32 = 72;
pub const LINUX_EDOTDOT: i32 = 73;
pub const LINUX_EBADMSG: i32 = 74;
pub const LINUX_EOVERFLOW: i32 = 75;
pub const LINUX_ENOTUNIQ: i32 = 76;
pub const LINUX_EBADFD: i32 = 77;
pub const LINUX_EREMCHG: i32 = 78;
pub const LINUX_ELIBACC: i32 = 79;
pub const LINUX_ELIBBAD: i32 = 80;
pub const LINUX_ELIBSCN: i32 = 81;
pub const LINUX_ELIBMAX: i32 = 82;
pub const LINUX_ELIBEXEC: i32 = 83;
pub const LINUX_EILSEQ: i32 = 84;
pub const LINUX_ERESTART: i32 = 85;
pub const LINUX_ESTRPIPE: i32 = 86;
pub const LINUX_EUSERS: i32 = 87;
pub const LINUX_ENOTSOCK: i32 = 88;
pub const LINUX_EDESTADDRREQ: i32 = 89;
pub const LINUX_EMSGSIZE: i32 = 90;
pub const LINUX_EPROTOTYPE: i32 = 91;
pub const LINUX_ENOPROTOOPT: i32 = 92;
pub const LINUX_EPROTONOTSUPPORT: i32 = 93;
pub const LINUX_ESOCKNOTSUPPORT: i32 = 94;
pub const LINUX_EOPNOTSUPPORT: i32 = 95;
pub const LINUX_EPFNOTSUPPORT: i32 = 96;
pub const LINUX_EAFNOTSUPPORT: i32 = 97;
pub const LINUX_EADDRINUSE: i32 = 98;
pub const LINUX_EADDRNOTAVAIL: i32 = 99;
pub const LINUX_ENETDOWN: i32 = 100;
pub const LINUX_ENETUNREACH: i32 = 101;
pub const LINUX_ENETRESET: i32 = 102;
pub const LINUX_ECONNABORTED: i32 = 103;
pub const LINUX_ECONNRESET: i32 = 104;
pub const LINUX_ENOBUFS: i32 = 105;
pub const LINUX_EISCONN: i32 = 106;
pub const LINUX_ENOTCONN: i32 = 107;
pub const LINUX_ESHUTDOWN: i32 = 108;
pub const LINUX_ETOOMANYREFS: i32 = 109;
pub const LINUX_ETIMEDOUT: i32 = 110;
pub const LINUX_ECONNREFUSED: i32 = 111;
pub const LINUX_EHOSTDOWN: i32 = 112;
pub const LINUX_EHOSTUNREACH: i32 = 113;
pub const LINUX_EALREADY: i32 = 114;
pub const LINUX_EINPROGRESS: i32 = 115;
pub const LINUX_ESTALE: i32 = 116;
pub const LINUX_EUCLEAN: i32 = 117;
pub const LINUX_ENOTNAM: i32 = 118;
pub const LINUX_ENAVAIL: i32 = 119;
pub const LINUX_EISNAM: i32 = 120;
pub const LINUX_EREMOTEIO: i32 = 121;
pub const LINUX_EDQUOT: i32 = 122;
pub const LINUX_ENOMEDIUM: i32 = 123;
pub const LINUX_EMEDIUMTYPE: i32 = 124;
pub const LINUX_ECANCELED: i32 = 125;
pub const LINUX_ENOKEY: i32 = 126;
pub const LINUX_EKEYEXPIRED: i32 = 127;
pub const LINUX_EKEYREVOKED: i32 = 128;
pub const LINUX_EKEYREJECTED: i32 = 129;
pub const LINUX_EOWNERDEAD: i32 = 130;
pub const LINUX_ENOTRECOVERABLE: i32 = 131;
pub const LINUX_ERFKILL: i32 = 132;
pub const LINUX_EHWPOISON: i32 = 133;
/// Highest Linux errno value.
pub const LINUX_ELAST: i32 = 133;

// ---------------------------------------------------------------------------
// BSD errno constants (sys/sys/errno.h)
// ---------------------------------------------------------------------------

pub const BSD_EPERM: i32 = 1;
pub const BSD_ENOENT: i32 = 2;
pub const BSD_ESRCH: i32 = 3;
pub const BSD_EINTR: i32 = 4;
pub const BSD_EIO: i32 = 5;
pub const BSD_ENXIO: i32 = 6;
pub const BSD_E2BIG: i32 = 7;
pub const BSD_ENOEXEC: i32 = 8;
pub const BSD_EBADF: i32 = 9;
pub const BSD_ECHILD: i32 = 10;
pub const BSD_EDEADLK: i32 = 11;
pub const BSD_ENOMEM: i32 = 12;
pub const BSD_EACCES: i32 = 13;
pub const BSD_EFAULT: i32 = 14;
pub const BSD_ENOTBLK: i32 = 15;
pub const BSD_EBUSY: i32 = 16;
pub const BSD_EEXIST: i32 = 17;
pub const BSD_EXDEV: i32 = 18;
pub const BSD_ENODEV: i32 = 19;
pub const BSD_ENOTDIR: i32 = 20;
pub const BSD_EISDIR: i32 = 21;
pub const BSD_EINVAL: i32 = 22;
pub const BSD_ENFILE: i32 = 23;
pub const BSD_EMFILE: i32 = 24;
pub const BSD_ENOTTY: i32 = 25;
pub const BSD_ETXTBSY: i32 = 26;
pub const BSD_EFBIG: i32 = 27;
pub const BSD_ENOSPC: i32 = 28;
pub const BSD_ESPIPE: i32 = 29;
pub const BSD_EROFS: i32 = 30;
pub const BSD_EMLINK: i32 = 31;
pub const BSD_EPIPE: i32 = 32;
pub const BSD_EDOM: i32 = 33;
pub const BSD_ERANGE: i32 = 34;
pub const BSD_EAGAIN: i32 = 35;
pub const BSD_EINPROGRESS: i32 = 36;
pub const BSD_EALREADY: i32 = 37;
pub const BSD_ENOTSOCK: i32 = 38;
pub const BSD_EDESTADDRREQ: i32 = 39;
pub const BSD_EMSGSIZE: i32 = 40;
pub const BSD_EPROTOTYPE: i32 = 41;
pub const BSD_ENOPROTOOPT: i32 = 42;
pub const BSD_EPROTONOSUPPORT: i32 = 43;
pub const BSD_ESOCKTNOSUPPORT: i32 = 44;
pub const BSD_EOPNOTSUPP: i32 = 45;
pub const BSD_EPFNOSUPPORT: i32 = 46;
pub const BSD_EAFNOSUPPORT: i32 = 47;
pub const BSD_EADDRINUSE: i32 = 48;
pub const BSD_EADDRNOTAVAIL: i32 = 49;
pub const BSD_ENETDOWN: i32 = 50;
pub const BSD_ENETUNREACH: i32 = 51;
pub const BSD_ENETRESET: i32 = 52;
pub const BSD_ECONNABORTED: i32 = 53;
pub const BSD_ECONNRESET: i32 = 54;
pub const BSD_ENOBUFS: i32 = 55;
pub const BSD_EISCONN: i32 = 56;
pub const BSD_ENOTCONN: i32 = 57;
pub const BSD_ESHUTDOWN: i32 = 58;
pub const BSD_ETOOMANYREFS: i32 = 59;
pub const BSD_ETIMEDOUT: i32 = 60;
pub const BSD_ECONNREFUSED: i32 = 61;
pub const BSD_ELOOP: i32 = 62;
pub const BSD_ENAMETOOLONG: i32 = 63;
pub const BSD_EHOSTDOWN: i32 = 64;
pub const BSD_EHOSTUNREACH: i32 = 65;
pub const BSD_ENOTEMPTY: i32 = 66;
pub const BSD_EPROCLIM: i32 = 67;
pub const BSD_EUSERS: i32 = 68;
pub const BSD_EDQUOT: i32 = 69;
pub const BSD_ESTALE: i32 = 70;
pub const BSD_EREMOTE: i32 = 71;
pub const BSD_EBADRPC: i32 = 72;
pub const BSD_ERPCMISMATCH: i32 = 73;
pub const BSD_EPROGUNAVAIL: i32 = 74;
pub const BSD_EPROGMISMATCH: i32 = 75;
pub const BSD_EPROCUNAVAIL: i32 = 76;
pub const BSD_ENOLCK: i32 = 77;
pub const BSD_ENOSYS: i32 = 78;
pub const BSD_EFTYPE: i32 = 79;
pub const BSD_EAUTH: i32 = 80;
pub const BSD_ENEEDAUTH: i32 = 81;
pub const BSD_EIDRM: i32 = 82;
pub const BSD_ENOMSG: i32 = 83;
pub const BSD_EOVERFLOW: i32 = 84;
pub const BSD_ECANCELED: i32 = 85;
pub const BSD_EILSEQ: i32 = 86;
pub const BSD_ENOATTR: i32 = 87;
pub const BSD_EDOOFUS: i32 = 88;
pub const BSD_EBADMSG: i32 = 89;
pub const BSD_EMULTIHOP: i32 = 90;
pub const BSD_ENOLINK: i32 = 91;
pub const BSD_EPROTO: i32 = 92;
pub const BSD_ENOTCAPABLE: i32 = 93;
pub const BSD_ECAPMODE: i32 = 94;
pub const BSD_ENOTRECOVERABLE: i32 = 95;
pub const BSD_EOWNERDEAD: i32 = 96;
pub const BSD_EINTEGRITY: i32 = 97;
/// Highest BSD errno value (ELAST).
pub const BSD_ELAST: i32 = 97;

// ---------------------------------------------------------------------------
// BSD -> Linux errno translation table
// Ported from FreeBSD linux_errtbl[ELAST + 1] in linux_errno.inc.
//
// Index = BSD errno, value = Linux errno.
// BSD-only errnos without a Linux equivalent are mapped to the closest
// match (annotated with "XXX" in FreeBSD source).
// ---------------------------------------------------------------------------

/// BSD-to-Linux errno mapping table. Index by BSD errno, get Linux errno.
///
/// Matches FreeBSD `linux_errtbl[]` exactly, but stores positive values
/// (FreeBSD stores negated values since Linux returns negative errno).
const BSD_TO_LINUX: [i32; 98] = {
    let mut t = [0i32; 98];
    // [0..9]
    t[0] = 0;
    t[1] = LINUX_EPERM;            // EPERM
    t[2] = LINUX_ENOENT;           // ENOENT
    t[3] = LINUX_ESRCH;            // ESRCH
    t[4] = LINUX_EINTR;            // EINTR
    t[5] = LINUX_EIO;              // EIO
    t[6] = LINUX_ENXIO;            // ENXIO
    t[7] = LINUX_E2BIG;            // E2BIG
    t[8] = LINUX_ENOEXEC;          // ENOEXEC
    t[9] = LINUX_EBADF;            // EBADF
    // [10..19]
    t[10] = LINUX_ECHILD;          // ECHILD
    t[11] = LINUX_EDEADLK;         // EDEADLK
    t[12] = LINUX_ENOMEM;          // ENOMEM
    t[13] = LINUX_EACCES;          // EACCES
    t[14] = LINUX_EFAULT;          // EFAULT
    t[15] = LINUX_ENOTBLK;         // ENOTBLK
    t[16] = LINUX_EBUSY;           // EBUSY
    t[17] = LINUX_EEXIST;          // EEXIST
    t[18] = LINUX_EXDEV;           // EXDEV
    t[19] = LINUX_ENODEV;          // ENODEV
    // [20..29]
    t[20] = LINUX_ENOTDIR;         // ENOTDIR
    t[21] = LINUX_EISDIR;          // EISDIR
    t[22] = LINUX_EINVAL;          // EINVAL
    t[23] = LINUX_ENFILE;          // ENFILE
    t[24] = LINUX_EMFILE;          // EMFILE
    t[25] = LINUX_ENOTTY;          // ENOTTY
    t[26] = LINUX_ETXTBSY;         // ETXTBSY
    t[27] = LINUX_EFBIG;           // EFBIG
    t[28] = LINUX_ENOSPC;          // ENOSPC
    t[29] = LINUX_ESPIPE;          // ESPIPE
    // [30..39]
    t[30] = LINUX_EROFS;           // EROFS
    t[31] = LINUX_EMLINK;          // EMLINK
    t[32] = LINUX_EPIPE;           // EPIPE
    t[33] = LINUX_EDOM;            // EDOM
    t[34] = LINUX_ERANGE;          // ERANGE
    t[35] = LINUX_EAGAIN;          // EAGAIN (BSD 35 -> Linux 11)
    t[36] = LINUX_EINPROGRESS;     // EINPROGRESS
    t[37] = LINUX_EALREADY;        // EALREADY
    t[38] = LINUX_ENOTSOCK;        // ENOTSOCK
    t[39] = LINUX_EDESTADDRREQ;    // EDESTADDRREQ
    // [40..49]
    t[40] = LINUX_EMSGSIZE;        // EMSGSIZE
    t[41] = LINUX_EPROTOTYPE;      // EPROTOTYPE
    t[42] = LINUX_ENOPROTOOPT;     // ENOPROTOOPT
    t[43] = LINUX_EPROTONOTSUPPORT; // EPROTONOSUPPORT
    t[44] = LINUX_ESOCKNOTSUPPORT; // ESOCKTNOSUPPORT
    t[45] = LINUX_EOPNOTSUPPORT;   // EOPNOTSUPP
    t[46] = LINUX_EPFNOTSUPPORT;   // EPFNOSUPPORT
    t[47] = LINUX_EAFNOTSUPPORT;   // EAFNOSUPPORT
    t[48] = LINUX_EADDRINUSE;      // EADDRINUSE
    t[49] = LINUX_EADDRNOTAVAIL;   // EADDRNOTAVAIL
    // [50..59]
    t[50] = LINUX_ENETDOWN;        // ENETDOWN
    t[51] = LINUX_ENETUNREACH;     // ENETUNREACH
    t[52] = LINUX_ENETRESET;       // ENETRESET
    t[53] = LINUX_ECONNABORTED;    // ECONNABORTED
    t[54] = LINUX_ECONNRESET;      // ECONNRESET
    t[55] = LINUX_ENOBUFS;         // ENOBUFS
    t[56] = LINUX_EISCONN;         // EISCONN
    t[57] = LINUX_ENOTCONN;        // ENOTCONN
    t[58] = LINUX_ESHUTDOWN;       // ESHUTDOWN
    t[59] = LINUX_ETOOMANYREFS;    // ETOOMANYREFS
    // [60..69]
    t[60] = LINUX_ETIMEDOUT;       // ETIMEDOUT
    t[61] = LINUX_ECONNREFUSED;    // ECONNREFUSED
    t[62] = LINUX_ELOOP;           // ELOOP
    t[63] = LINUX_ENAMETOOLONG;    // ENAMETOOLONG
    t[64] = LINUX_EHOSTDOWN;       // EHOSTDOWN
    t[65] = LINUX_EHOSTUNREACH;    // EHOSTUNREACH
    t[66] = LINUX_ENOTEMPTY;       // ENOTEMPTY
    t[67] = LINUX_EAGAIN;          // EPROCLIM -> EAGAIN (XXX)
    t[68] = LINUX_EUSERS;          // EUSERS
    t[69] = LINUX_EDQUOT;          // EDQUOT
    // [70..79]
    t[70] = LINUX_ESTALE;          // ESTALE
    t[71] = LINUX_EREMOTE;         // EREMOTE
    t[72] = LINUX_ENXIO;           // EBADRPC -> ENXIO (XXX)
    t[73] = LINUX_ENXIO;           // ERPCMISMATCH -> ENXIO (XXX)
    t[74] = LINUX_ENXIO;           // EPROGUNAVAIL -> ENXIO (XXX)
    t[75] = LINUX_ENXIO;           // EPROGMISMATCH -> ENXIO (XXX)
    t[76] = LINUX_ENXIO;           // EPROCUNAVAIL -> ENXIO (XXX)
    t[77] = LINUX_ENOLCK;          // ENOLCK
    t[78] = LINUX_ENOSYS;          // ENOSYS
    t[79] = LINUX_EBADF;           // EFTYPE -> EBADF (XXX)
    // [80..89]
    t[80] = LINUX_ENXIO;           // EAUTH -> ENXIO (XXX)
    t[81] = LINUX_ENXIO;           // ENEEDAUTH -> ENXIO (XXX)
    t[82] = LINUX_EIDRM;           // EIDRM
    t[83] = LINUX_ENOMSG;          // ENOMSG
    t[84] = LINUX_EOVERFLOW;       // EOVERFLOW
    t[85] = LINUX_ECANCELED;       // ECANCELED
    t[86] = LINUX_EILSEQ;          // EILSEQ
    t[87] = LINUX_ENODATA;         // ENOATTR -> ENODATA (XXX)
    t[88] = LINUX_EINVAL;          // EDOOFUS -> EINVAL (XXX)
    t[89] = LINUX_EBADMSG;         // EBADMSG
    // [90..97]
    t[90] = LINUX_EMULTIHOP;       // EMULTIHOP
    t[91] = LINUX_ENOLINK;         // ENOLINK
    t[92] = LINUX_EPROTO;          // EPROTO
    t[93] = LINUX_EPERM;           // ENOTCAPABLE -> EPERM (XXX)
    t[94] = LINUX_EPERM;           // ECAPMODE -> EPERM (XXX)
    t[95] = LINUX_ENOTRECOVERABLE; // ENOTRECOVERABLE
    t[96] = LINUX_EOWNERDEAD;      // EOWNERDEAD
    t[97] = LINUX_EINVAL;          // EINTEGRITY -> EINVAL (XXX)
    t
};

// ---------------------------------------------------------------------------
// Linux -> BSD errno translation table
// Ported from FreeBSD linux_to_bsd_errtbl[LINUX_ELAST + 1] in linux_errno.inc.
//
// Index = Linux errno, value = BSD errno.
// Linux-only errnos (device/stream/lib errors 44..86) map to EINVAL.
// ---------------------------------------------------------------------------

/// Linux-to-BSD errno mapping table. Index by Linux errno, get BSD errno.
const LINUX_TO_BSD: [i32; 134] = {
    let mut t = [0i32; 134];
    // [0..9]
    t[0] = 0;
    t[1] = BSD_EPERM;              // LINUX_EPERM
    t[2] = BSD_ENOENT;             // LINUX_ENOENT
    t[3] = BSD_ESRCH;              // LINUX_ESRCH
    t[4] = BSD_EINTR;              // LINUX_EINTR
    t[5] = BSD_EIO;                // LINUX_EIO
    t[6] = BSD_ENXIO;              // LINUX_ENXIO
    t[7] = BSD_E2BIG;              // LINUX_E2BIG
    t[8] = BSD_ENOENT;             // LINUX_ENOEXEC -> ENOENT (FreeBSD)
    t[9] = BSD_EBADF;              // LINUX_EBADF
    // [10..19]
    t[10] = BSD_ECHILD;            // LINUX_ECHILD
    t[11] = BSD_EAGAIN;            // LINUX_EAGAIN
    t[12] = BSD_ENOMEM;            // LINUX_ENOMEM
    t[13] = BSD_EACCES;            // LINUX_EACCES
    t[14] = BSD_EFAULT;            // LINUX_EFAULT
    t[15] = BSD_ENOTBLK;           // LINUX_ENOTBLK
    t[16] = BSD_EBUSY;             // LINUX_EBUSY
    t[17] = BSD_EEXIST;            // LINUX_EEXIST
    t[18] = BSD_EXDEV;             // LINUX_EXDEV
    t[19] = BSD_ENODEV;            // LINUX_ENODEV
    // [20..29]
    t[20] = BSD_ENOTDIR;           // LINUX_ENOTDIR
    t[21] = BSD_EISDIR;            // LINUX_EISDIR
    t[22] = BSD_EINVAL;            // LINUX_EINVAL
    t[23] = BSD_ENFILE;            // LINUX_ENFILE
    t[24] = BSD_EMFILE;            // LINUX_EMFILE
    t[25] = BSD_ENOTTY;            // LINUX_ENOTTY
    t[26] = BSD_ETXTBSY;           // LINUX_ETXTBSY
    t[27] = BSD_EFBIG;             // LINUX_EFBIG
    t[28] = BSD_ENOSPC;            // LINUX_ENOSPC
    t[29] = BSD_ESPIPE;            // LINUX_ESPIPE
    // [30..39]
    t[30] = BSD_EROFS;             // LINUX_EROFS
    t[31] = BSD_EMLINK;            // LINUX_EMLINK
    t[32] = BSD_EPIPE;             // LINUX_EPIPE
    t[33] = BSD_EDOM;              // LINUX_EDOM
    t[34] = BSD_ERANGE;            // LINUX_ERANGE
    t[35] = BSD_EDEADLK;           // LINUX_EDEADLK
    t[36] = BSD_ENAMETOOLONG;      // LINUX_ENAMETOOLONG
    t[37] = BSD_ENOLCK;            // LINUX_ENOLCK
    t[38] = BSD_ENOSYS;            // LINUX_ENOSYS
    t[39] = BSD_ENOTEMPTY;         // LINUX_ENOTEMPTY
    // [40..49]
    t[40] = BSD_ELOOP;             // LINUX_ELOOP
    t[41] = BSD_EINVAL;            // gap (no Linux errno 41)
    t[42] = BSD_ENOMSG;            // LINUX_ENOMSG
    t[43] = BSD_EIDRM;             // LINUX_EIDRM
    t[44] = BSD_EINVAL;            // LINUX_ECHRNG (XXX)
    t[45] = BSD_EINVAL;            // LINUX_EL2NSYNC (XXX)
    t[46] = BSD_EINVAL;            // LINUX_EL3HLT (XXX)
    t[47] = BSD_EINVAL;            // LINUX_EL3RST (XXX)
    t[48] = BSD_EINVAL;            // LINUX_ELNRNG (XXX)
    t[49] = BSD_EINVAL;            // LINUX_EUNATCH (XXX)
    // [50..59]
    t[50] = BSD_EINVAL;            // LINUX_ENOCSI (XXX)
    t[51] = BSD_EINVAL;            // LINUX_EL2HLT (XXX)
    t[52] = BSD_EINVAL;            // LINUX_EBADE (XXX)
    t[53] = BSD_EINVAL;            // LINUX_EBADR (XXX)
    t[54] = BSD_EINVAL;            // LINUX_EXFULL (XXX)
    t[55] = BSD_EINVAL;            // LINUX_ENOANO (XXX)
    t[56] = BSD_EINVAL;            // LINUX_EBADRQC (XXX)
    t[57] = BSD_EINVAL;            // LINUX_EBADSLT (XXX)
    t[58] = BSD_EINVAL;            // gap
    t[59] = BSD_EINVAL;            // LINUX_EBFONT (XXX)
    // [60..69]
    t[60] = BSD_EINVAL;            // LINUX_ENOSTR (XXX)
    t[61] = BSD_ENOATTR;           // LINUX_ENODATA -> ENOATTR (XXX)
    t[62] = BSD_EINVAL;            // LINUX_ENOTIME (XXX)
    t[63] = BSD_EINVAL;            // LINUX_ENOSR (XXX)
    t[64] = BSD_EINVAL;            // LINUX_ENONET (XXX)
    t[65] = BSD_EINVAL;            // LINUX_ENOPKG (XXX)
    t[66] = BSD_EREMOTE;           // LINUX_EREMOTE
    t[67] = BSD_ENOLINK;           // LINUX_ENOLINK
    t[68] = BSD_EINVAL;            // LINUX_EADV (XXX)
    t[69] = BSD_EINVAL;            // LINUX_ESRMNT (XXX)
    // [70..79]
    t[70] = BSD_EINVAL;            // LINUX_ECOMM (XXX)
    t[71] = BSD_EPROTO;            // LINUX_EPROTO
    t[72] = BSD_EMULTIHOP;         // LINUX_EMULTIHOP
    t[73] = BSD_EINVAL;            // LINUX_EDOTDOT (XXX)
    t[74] = BSD_EBADMSG;           // LINUX_EBADMSG
    t[75] = BSD_EOVERFLOW;         // LINUX_EOVERFLOW
    t[76] = BSD_EINVAL;            // LINUX_ENOTUNIQ (XXX)
    t[77] = BSD_EBADF;             // LINUX_EBADFD -> EBADF (XXX)
    t[78] = BSD_EINVAL;            // LINUX_EREMCHG (XXX)
    t[79] = BSD_EINVAL;            // LINUX_ELIBACC (XXX)
    // [80..89]
    t[80] = BSD_EINVAL;            // LINUX_ELIBBAD (XXX)
    t[81] = BSD_EINVAL;            // LINUX_ELIBSCN (XXX)
    t[82] = BSD_EINVAL;            // LINUX_ELIBMAX (XXX)
    t[83] = BSD_EINVAL;            // LINUX_ELIBEXEC (XXX)
    t[84] = BSD_EILSEQ;            // LINUX_EILSEQ
    t[85] = BSD_EAGAIN;            // LINUX_ERESTART -> EAGAIN (XXX)
    t[86] = BSD_EINVAL;            // LINUX_ESTRPIPE (XXX)
    t[87] = BSD_EUSERS;            // LINUX_EUSERS
    t[88] = BSD_ENOTSOCK;          // LINUX_ENOTSOCK
    t[89] = BSD_EDESTADDRREQ;      // LINUX_EDESTADDRREQ
    // [90..99]
    t[90] = BSD_EMSGSIZE;          // LINUX_EMSGSIZE
    t[91] = BSD_EPROTOTYPE;        // LINUX_EPROTOTYPE
    t[92] = BSD_ENOPROTOOPT;       // LINUX_ENOPROTOOPT
    t[93] = BSD_EPROTONOSUPPORT;   // LINUX_EPROTONOTSUPPORT
    t[94] = BSD_EPROTONOSUPPORT;   // LINUX_ESOCKNOTSUPPORT -> EPROTONOSUPPORT (XXX)
    t[95] = BSD_EOPNOTSUPP;        // LINUX_EOPNOTSUPPORT
    t[96] = BSD_EPFNOSUPPORT;      // LINUX_EPFNOTSUPPORT
    t[97] = BSD_EAFNOSUPPORT;      // LINUX_EAFNOTSUPPORT
    t[98] = BSD_EADDRINUSE;        // LINUX_EADDRINUSE
    t[99] = BSD_EADDRNOTAVAIL;     // LINUX_EADDRNOTAVAIL
    // [100..109]
    t[100] = BSD_ENETDOWN;         // LINUX_ENETDOWN
    t[101] = BSD_ENETUNREACH;      // LINUX_ENETUNREACH
    t[102] = BSD_ENETRESET;        // LINUX_ENETRESET
    t[103] = BSD_ECONNABORTED;     // LINUX_ECONNABORTED
    t[104] = BSD_ECONNRESET;       // LINUX_ECONNRESET
    t[105] = BSD_ENOBUFS;          // LINUX_ENOBUFS
    t[106] = BSD_EISCONN;          // LINUX_EISCONN
    t[107] = BSD_ENOTCONN;         // LINUX_ENOTCONN
    t[108] = BSD_ESHUTDOWN;        // LINUX_ESHUTDOWN
    t[109] = BSD_ETOOMANYREFS;     // LINUX_ETOOMANYREFS
    // [110..119]
    t[110] = BSD_ETIMEDOUT;        // LINUX_ETIMEDOUT
    t[111] = BSD_ECONNREFUSED;     // LINUX_ECONNREFUSED
    t[112] = BSD_EHOSTDOWN;        // LINUX_EHOSTDOWN
    t[113] = BSD_EHOSTUNREACH;     // LINUX_EHOSTUNREACH
    t[114] = BSD_EALREADY;         // LINUX_EALREADY
    t[115] = BSD_EINPROGRESS;      // LINUX_EINPROGRESS
    t[116] = BSD_ESTALE;           // LINUX_ESTALE
    t[117] = BSD_EINVAL;           // LINUX_EUCLEAN (XXX)
    t[118] = BSD_EINVAL;           // LINUX_ENOTNAM (XXX)
    t[119] = BSD_EINVAL;           // LINUX_ENAVAIL (XXX)
    // [120..129]
    t[120] = BSD_EINVAL;           // LINUX_EISNAM (XXX)
    t[121] = BSD_EINVAL;           // LINUX_EREMOTEIO (XXX)
    t[122] = BSD_EDQUOT;           // LINUX_EDQUOT
    t[123] = BSD_EIO;              // LINUX_ENOMEDIUM -> EIO (XXX)
    t[124] = BSD_EIO;              // LINUX_EMEDIUMTYPE -> EIO (XXX)
    t[125] = BSD_ECANCELED;        // LINUX_ECANCELED
    t[126] = BSD_EIO;              // LINUX_ENOKEY -> EIO (XXX)
    t[127] = BSD_EIO;              // LINUX_EKEYEXPIRED -> EIO (XXX)
    t[128] = BSD_EIO;              // LINUX_EKEYREVOKED -> EIO (XXX)
    t[129] = BSD_EIO;              // LINUX_EKEYREJECTED -> EIO (XXX)
    // [130..133]
    t[130] = BSD_EOWNERDEAD;       // LINUX_EOWNERDEAD
    t[131] = BSD_ENOTRECOVERABLE;  // LINUX_ENOTRECOVERABLE
    t[132] = BSD_ENETDOWN;         // LINUX_ERFKILL -> ENETDOWN (XXX)
    t[133] = BSD_EINVAL;           // LINUX_EHWPOISON -> EINVAL (XXX)
    t
};

/// Map a BSD errno (positive) to the corresponding Linux errno (positive).
///
/// Returns 0 for unknown/out-of-range values. The caller should negate the
/// result before returning to a Linux process.
pub const fn bsd_to_linux_errno(bsd: i32) -> i32 {
    if bsd < 0 || bsd > BSD_ELAST {
        0
    } else {
        BSD_TO_LINUX[bsd as usize]
    }
}

/// Map a Linux errno (positive) to the corresponding BSD errno (positive).
///
/// Returns EINVAL for unknown/out-of-range values.
pub const fn linux_to_bsd_errno(linux: i32) -> i32 {
    if linux < 0 || linux > LINUX_ELAST {
        BSD_EINVAL
    } else {
        LINUX_TO_BSD[linux as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_common_errnos() {
        // Errnos 1..34 are identical between Linux and BSD.
        for i in 1..=34 {
            assert_eq!(bsd_to_linux_errno(i), i, "bsd {i} should map to linux {i}");
        }
    }

    #[test]
    fn eagain_diverges() {
        // BSD EAGAIN = 35, Linux EAGAIN = 11.
        assert_eq!(bsd_to_linux_errno(BSD_EAGAIN), LINUX_EAGAIN);
        assert_eq!(linux_to_bsd_errno(LINUX_EAGAIN), BSD_EAGAIN);
    }

    #[test]
    fn network_errnos() {
        assert_eq!(bsd_to_linux_errno(BSD_ECONNREFUSED), LINUX_ECONNREFUSED);
        assert_eq!(linux_to_bsd_errno(LINUX_ECONNREFUSED), BSD_ECONNREFUSED);
        assert_eq!(bsd_to_linux_errno(BSD_ETIMEDOUT), LINUX_ETIMEDOUT);
        assert_eq!(linux_to_bsd_errno(LINUX_ETIMEDOUT), BSD_ETIMEDOUT);
    }

    #[test]
    fn bsd_only_errnos() {
        // BSD-only errnos should map to something reasonable.
        assert_eq!(bsd_to_linux_errno(BSD_EPROCLIM), LINUX_EAGAIN);
        assert_eq!(bsd_to_linux_errno(BSD_EBADRPC), LINUX_ENXIO);
        assert_eq!(bsd_to_linux_errno(BSD_ECAPMODE), LINUX_EPERM);
    }

    #[test]
    fn linux_only_errnos() {
        // Linux-only device/stream errnos should map to EINVAL.
        assert_eq!(linux_to_bsd_errno(LINUX_ECHRNG), BSD_EINVAL);
        assert_eq!(linux_to_bsd_errno(LINUX_ELIBBAD), BSD_EINVAL);
        // Key management errnos map to EIO.
        assert_eq!(linux_to_bsd_errno(LINUX_ENOKEY), BSD_EIO);
    }

    #[test]
    fn out_of_range() {
        assert_eq!(bsd_to_linux_errno(-1), 0);
        assert_eq!(bsd_to_linux_errno(9999), 0);
        assert_eq!(linux_to_bsd_errno(-1), BSD_EINVAL);
        assert_eq!(linux_to_bsd_errno(9999), BSD_EINVAL);
    }
}
