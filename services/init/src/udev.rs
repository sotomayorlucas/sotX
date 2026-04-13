// ---------------------------------------------------------------------------
// udev stub — synthetic /sys/ entries for DRM device enumeration
//
// Weston's drm-backend uses libudev to find /dev/dri/card0.
// libudev reads from /sys/class/drm/ and /sys/devices/.../drm/card0/.
// We serve these paths as virtual files so libudev finds our DRM device.
// ---------------------------------------------------------------------------

use crate::exec::starts_with;

/// Check if a path is a synthetic /sys/ entry for DRM.
/// Returns Some(content) if we should serve it, None otherwise.
pub(crate) fn sys_class_drm_content(path: &[u8]) -> Option<&'static [u8]> {
    // /sys/class/drm/card0/dev → "226:0\n" (major:minor)
    if path == b"/sys/class/drm/card0/dev" { return Some(b"226:0\n"); }
    // /sys/class/drm/card0/uevent
    if path == b"/sys/class/drm/card0/uevent" {
        return Some(b"MAJOR=226\nMINOR=0\nDEVNAME=dri/card0\nDEVTYPE=drm_minor\nSUBSYSTEM=drm\n");
    }
    // /sys/dev/char/226:0 → device path (libudev uses this)
    if path == b"/sys/dev/char/226:0/uevent" {
        return Some(b"MAJOR=226\nMINOR=0\nDEVNAME=dri/card0\nDEVTYPE=drm_minor\nSUBSYSTEM=drm\n");
    }
    if path == b"/sys/dev/char/226:0/dev" { return Some(b"226:0\n"); }
    // /sys/class/drm/card0/device/driver → driver name
    if path == b"/sys/class/drm/card0/device/driver" { return Some(b"sotX-drm"); }
    // sysattr: boot_vga (weston checks this)
    if path == b"/sys/class/drm/card0/device/boot_vga"
        || path == b"/sys/devices/pci0000:00/0000:00:02.0/boot_vga" { return Some(b"1\n"); }
    // /sys/devices path for the device
    if path == b"/sys/devices/pci0000:00/0000:00:02.0/drm/card0/dev" { return Some(b"226:0\n"); }
    if path == b"/sys/devices/pci0000:00/0000:00:02.0/drm/card0/uevent" {
        return Some(b"MAJOR=226\nMINOR=0\nDEVNAME=dri/card0\nDEVTYPE=drm_minor\nSUBSYSTEM=drm\n");
    }
    // Parent PCI device uevent (libudev walks up the device tree)
    if path == b"/sys/devices/pci0000:00/0000:00:02.0/uevent" {
        return Some(b"PCI_ID=1234:1111\nPCI_SUBSYS_ID=1AF4:1100\nPCI_SLOT_NAME=0000:00:02.0\nDRIVER=sotX-drm\nSUBSYSTEM=pci\n");
    }
    // subsystem link targets (content served as virtual file)
    if path == b"/sys/devices/pci0000:00/0000:00:02.0/drm/card0/subsystem" {
        return Some(b"/sys/class/drm");
    }
    // Input subsystem links
    if path == b"/sys/devices/virtual/input/input0/event0/subsystem" {
        return Some(b"/sys/class/input");
    }
    if path == b"/sys/devices/virtual/input/input1/event1/subsystem" {
        return Some(b"/sys/class/input");
    }
    // Parent input device info
    if path == b"/sys/devices/virtual/input/input0/uevent" {
        return Some(b"PRODUCT=6/1/1/1\nNAME=\"sotX Virtual Keyboard\"\nPHYS=\"\"\nUNIQ=\"\"\nPROP=0\nEV=120013\nKEY=fffffffffffffffe\nMSC=10\nREP=2\n");
    }
    if path == b"/sys/devices/virtual/input/input1/uevent" {
        return Some(b"PRODUCT=6/1/2/1\nNAME=\"sotX Virtual Mouse\"\nPHYS=\"\"\nUNIQ=\"\"\nPROP=0\nEV=7\nKEY=70000 0 0 0 0\nREL=103\n");
    }
    // seat assignment
    if path == b"/sys/class/drm/card0/device/id_seat"
        || starts_with(path, b"/sys/devices/pci0000:00/0000:00:02.0/id_seat") { return Some(b"seat0"); }
    // status: always connected
    if path == b"/sys/class/drm/card0-Virtual-1/status" { return Some(b"connected\n"); }
    if path == b"/sys/class/drm/card0-Virtual-1/enabled" { return Some(b"enabled\n"); }

    // -----------------------------------------------------------------------
    // Input devices — libinput/udev enumeration for /dev/input/event0 (kbd)
    // and /dev/input/event1 (mouse)
    // -----------------------------------------------------------------------
    // /sys/class/input/event0
    if path == b"/sys/class/input/event0/dev" { return Some(b"13:64\n"); }
    if path == b"/sys/class/input/event0/uevent" {
        return Some(b"MAJOR=13\nMINOR=64\nDEVNAME=input/event0\nSUBSYSTEM=input\nID_SEAT=seat0\nID_INPUT=1\nID_INPUT_KEYBOARD=1\n");
    }
    if path == b"/sys/class/input/event1/dev" { return Some(b"13:65\n"); }
    if path == b"/sys/class/input/event1/uevent" {
        return Some(b"MAJOR=13\nMINOR=65\nDEVNAME=input/event1\nSUBSYSTEM=input\nID_SEAT=seat0\nID_INPUT=1\nID_INPUT_MOUSE=1\n");
    }
    // Device paths for libinput
    if path == b"/sys/devices/virtual/input/input0/event0/dev" { return Some(b"13:64\n"); }
    if path == b"/sys/devices/virtual/input/input0/event0/uevent" {
        return Some(b"MAJOR=13\nMINOR=64\nDEVNAME=input/event0\nSUBSYSTEM=input\nID_SEAT=seat0\nID_INPUT=1\nID_INPUT_KEYBOARD=1\n");
    }
    if path == b"/sys/devices/virtual/input/input1/event1/dev" { return Some(b"13:65\n"); }
    if path == b"/sys/devices/virtual/input/input1/event1/uevent" {
        return Some(b"MAJOR=13\nMINOR=65\nDEVNAME=input/event1\nSUBSYSTEM=input\nID_SEAT=seat0\nID_INPUT=1\nID_INPUT_MOUSE=1\n");
    }
    // Capabilities (libinput uses these to classify devices)
    if path == b"/sys/devices/virtual/input/input0/capabilities/ev" { return Some(b"120013\n"); } // EV_SYN|EV_KEY|EV_MSC|EV_REP
    if path == b"/sys/devices/virtual/input/input0/capabilities/key" { return Some(b"fffffffffffffffe\n"); }
    if path == b"/sys/devices/virtual/input/input1/capabilities/ev" { return Some(b"7\n"); } // EV_SYN|EV_KEY|EV_REL
    if path == b"/sys/devices/virtual/input/input1/capabilities/rel" { return Some(b"103\n"); } // REL_X|REL_Y|REL_WHEEL
    if path == b"/sys/devices/virtual/input/input1/capabilities/key" { return Some(b"70000 0 0 0 0\n"); } // BTN_LEFT+RIGHT+MIDDLE
    // seat tags
    if path == b"/sys/devices/virtual/input/input0/id_seat"
        || path == b"/sys/devices/virtual/input/input1/id_seat" { return Some(b"seat0"); }
    // dev/char for input
    if path == b"/sys/dev/char/13:64/uevent" {
        return Some(b"MAJOR=13\nMINOR=64\nDEVNAME=input/event0\nSUBSYSTEM=input\nID_SEAT=seat0\nID_INPUT=1\nID_INPUT_KEYBOARD=1\n");
    }
    if path == b"/sys/dev/char/13:65/uevent" {
        return Some(b"MAJOR=13\nMINOR=65\nDEVNAME=input/event1\nSUBSYSTEM=input\nID_SEAT=seat0\nID_INPUT=1\nID_INPUT_MOUSE=1\n");
    }

    // udev database files — libudev reads /run/udev/data/cMAJOR:MINOR for properties/tags
    if path == b"/run/udev/data/c226:0" {
        return Some(b"E:ID_SEAT=seat0\nE:SUBSYSTEM=drm\nE:DEVTYPE=drm_minor\nG:seat\n");
    }
    if path == b"/run/udev/data/c13:64" {
        return Some(b"E:ID_SEAT=seat0\nE:ID_INPUT=1\nE:ID_INPUT_KEYBOARD=1\nE:SUBSYSTEM=input\nG:seat\nG:uaccess\n");
    }
    if path == b"/run/udev/data/c13:65" {
        return Some(b"E:ID_SEAT=seat0\nE:ID_INPUT=1\nE:ID_INPUT_MOUSE=1\nE:SUBSYSTEM=input\nG:seat\nG:uaccess\n");
    }

    None
}

/// Check if a path is a synthetic /sys/ directory for DRM or input.
pub(crate) fn is_sys_drm_dir(path: &[u8]) -> bool {
    path == b"/sys/class"
        || path == b"/sys/class/"
        || path == b"/sys/class/drm"
        || path == b"/sys/class/drm/"
        || path == b"/sys/class/drm/card0"
        || path == b"/sys/class/drm/card0/"
        || path == b"/sys/class/drm/card0/device"
        || path == b"/sys/dev/char/226:0"
        || path == b"/sys/devices/pci0000:00/0000:00:02.0"
        || path == b"/sys/devices/pci0000:00/0000:00:02.0/drm"
        || path == b"/sys/devices/pci0000:00/0000:00:02.0/drm/card0"
        || starts_with(path, b"/sys/class/drm/card0/")
        || starts_with(path, b"/sys/devices/pci0000:00/0000:00:02.0/")
        || starts_with(path, b"/sys/dev/char/226:")
        // Input device directories
        || path == b"/sys/class/input"
        || path == b"/sys/class/input/"
        || starts_with(path, b"/sys/class/input/event")
        || starts_with(path, b"/sys/devices/virtual/input/")
        || starts_with(path, b"/sys/dev/char/13:")
}

/// Content for getdents64 on /sys/class/drm/ → list "card0"
pub(crate) fn sys_class_drm_entries() -> &'static [&'static [u8]] {
    &[b"card0"]
}

/// readlink for /sys/ symlinks → relative device syspaths
/// Real Linux uses relative symlinks: /sys/class/drm/card0 → ../../devices/pci.../drm/card0
pub(crate) fn sys_drm_readlink(path: &[u8]) -> Option<&'static [u8]> {
    if path == b"/sys/class/drm/card0" {
        Some(b"../../devices/pci0000:00/0000:00:02.0/drm/card0")
    } else if path == b"/sys/dev/char/226:0" {
        Some(b"../../devices/pci0000:00/0000:00:02.0/drm/card0")
    } else if path == b"/sys/class/input/event0" {
        Some(b"../../devices/virtual/input/input0/event0")
    } else if path == b"/sys/class/input/event1" {
        Some(b"../../devices/virtual/input/input1/event1")
    } else if path == b"/sys/dev/char/13:64" {
        Some(b"../../devices/virtual/input/input0/event0")
    } else if path == b"/sys/dev/char/13:65" {
        Some(b"../../devices/virtual/input/input1/event1")
    } else if path == b"/sys/devices/virtual/input/input0/event0/subsystem" {
        Some(b"../../../../class/input")
    } else if path == b"/sys/devices/virtual/input/input1/event1/subsystem" {
        Some(b"../../../../class/input")
    } else if path == b"/sys/devices/pci0000:00/0000:00:02.0/drm/card0/subsystem" {
        Some(b"../../../../class/drm")
    } else {
        None
    }
}

/// Content for getdents64 on /sys/class/input/ → list input events
pub(crate) fn sys_class_input_entries() -> &'static [&'static [u8]] {
    &[b"event0", b"event1"]
}
