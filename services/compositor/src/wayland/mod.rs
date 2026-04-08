//! Wayland wire protocol -- manual no_std parser and dispatcher.
//!
//! Wayland messages have a fixed header:
//!   object_id: u32   -- target object
//!   size_opcode: u32 -- upper 16 = size (bytes, including header), lower 16 = opcode
//! Followed by arguments (padded to 4-byte boundaries).
//!
//! Transport over sotOS IPC:
//!   tag[15:0]  = WL_MSG_TAG (0x574C) to distinguish from control messages
//!   tag[31:16] = byte count of wire data in regs[]
//!   regs[0..7] = raw Wayland wire bytes (up to 64 bytes)
//!
//! Response events are sent back the same way: tag = WL_MSG_TAG | (len << 16),
//! with serialized event bytes packed into regs[0..7].

pub mod display;
pub mod registry;
pub mod compositor;
pub mod shm;
pub mod shell;
pub mod seat;
pub mod xdg_popup;
pub mod layer_shell;
pub mod fractional_scale;

use sotos_common::IpcMsg;

/// Maximum message payload size (4 KiB including header).
pub const MAX_MSG_SIZE: usize = 4096;

/// Maximum file descriptors per message (SCM_RIGHTS).
pub const MAX_FDS: usize = 4;

/// IPC tag identifying a Wayland wire protocol message.
pub const WL_MSG_TAG: u64 = 0x574C; // "WL"

/// IPC tag for a new client connection request.
pub const WL_CONNECT_TAG: u64 = 0x574C_434F; // "WLCO"

/// IPC tag for SHM pool creation response.
/// regs[0] = shm_handle (kernel SHM object index)
/// regs[1] = page_count (number of 4K pages)
/// regs[2] = pool_id (Wayland object ID of the wl_shm_pool)
pub const WL_SHM_POOL_TAG: u64 = 0x574C_5348; // "WLSH"

/// Maximum bytes carried per IPC message (8 regs * 8 bytes).
pub const IPC_DATA_MAX: usize = 64;

/// Maximum events queued per dispatch round.
pub const MAX_EVENTS: usize = 16;

/// A parsed Wayland message.
pub struct WlMessage {
    pub object_id: u32,
    pub opcode: u16,
    pub size: u16,
    pub data: [u8; MAX_MSG_SIZE],
    pub data_len: usize,
    pub fds: [i32; MAX_FDS],
    pub fd_count: usize,
}

impl WlMessage {
    pub const fn empty() -> Self {
        Self {
            object_id: 0,
            opcode: 0,
            size: 0,
            data: [0; MAX_MSG_SIZE],
            data_len: 0,
            fds: [-1; MAX_FDS],
            fd_count: 0,
        }
    }

    /// Parse a message header from a raw byte buffer.
    /// Returns Some(bytes_consumed) on success.
    pub fn parse_header(&mut self, buf: &[u8]) -> Option<usize> {
        if buf.len() < 8 {
            return None;
        }

        self.object_id = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let size_opcode = u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]);
        self.opcode = (size_opcode & 0xFFFF) as u16;
        self.size = (size_opcode >> 16) as u16;

        let total = self.size as usize;
        if total < 8 || total > MAX_MSG_SIZE || buf.len() < total {
            return None;
        }

        // Copy payload (everything after the 8-byte header)
        let payload_len = total - 8;
        self.data[..payload_len].copy_from_slice(&buf[8..total]);
        self.data_len = payload_len;

        Some(total)
    }

    /// Read a u32 argument at byte offset within the payload.
    pub fn arg_u32(&self, offset: usize) -> u32 {
        if offset + 4 > self.data_len {
            return 0;
        }
        u32::from_ne_bytes([
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
        ])
    }

    /// Read a i32 argument at byte offset within the payload.
    pub fn arg_i32(&self, offset: usize) -> i32 {
        self.arg_u32(offset) as i32
    }

    /// Read a string argument at byte offset (length-prefixed, padded).
    /// Returns (string bytes, total consumed including padding).
    pub fn arg_string<'a>(&'a self, offset: usize) -> (&'a [u8], usize) {
        let len = self.arg_u32(offset) as usize;
        if len == 0 || offset + 4 + len > self.data_len {
            return (&[], 4);
        }
        // String includes NUL terminator in the length; actual string is len-1 bytes.
        let str_bytes = &self.data[offset + 4..offset + 4 + len - 1];
        // Pad to 4-byte boundary
        let padded = (len + 3) & !3;
        (str_bytes, 4 + padded)
    }
}

/// A Wayland event/response to be sent to the client.
pub struct WlEvent {
    pub buf: [u8; MAX_MSG_SIZE],
    pub len: usize,
}

impl WlEvent {
    pub const fn new() -> Self {
        Self {
            buf: [0; MAX_MSG_SIZE],
            len: 0,
        }
    }

    /// Start building an event for the given object and opcode.
    pub fn begin(&mut self, object_id: u32, opcode: u16) {
        self.len = 8; // reserve header
        let id_bytes = object_id.to_ne_bytes();
        self.buf[0..4].copy_from_slice(&id_bytes);
        // Opcode stored temporarily; size filled on finish()
        let op_bytes = (opcode as u32).to_ne_bytes();
        self.buf[4..8].copy_from_slice(&op_bytes);
    }

    /// Append a u32 argument.
    pub fn put_u32(&mut self, val: u32) {
        let bytes = val.to_ne_bytes();
        self.buf[self.len..self.len + 4].copy_from_slice(&bytes);
        self.len += 4;
    }

    /// Append an i32 argument.
    pub fn put_i32(&mut self, val: i32) {
        self.put_u32(val as u32);
    }

    /// Append a string argument (length-prefixed, NUL-terminated, padded).
    pub fn put_string(&mut self, s: &[u8]) {
        let len_with_nul = s.len() + 1;
        self.put_u32(len_with_nul as u32);
        self.buf[self.len..self.len + s.len()].copy_from_slice(s);
        self.buf[self.len + s.len()] = 0; // NUL
        let padded = (len_with_nul + 3) & !3;
        self.len += padded;
    }

    /// Finalize the event: write the size into the header.
    pub fn finish(&mut self) {
        let size_opcode = ((self.len as u32) << 16) | (u32::from_ne_bytes([
            self.buf[4], self.buf[5], self.buf[6], self.buf[7],
        ]) & 0xFFFF);
        self.buf[4..8].copy_from_slice(&size_opcode.to_ne_bytes());
    }

    /// Get the finalized message bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// Global object IDs for well-known Wayland globals.
pub const WL_DISPLAY_ID: u32 = 1;

/// Interface names for global advertisement.
pub const WL_COMPOSITOR_INTERFACE: &[u8] = b"wl_compositor";
pub const WL_SHM_INTERFACE: &[u8] = b"wl_shm";
pub const XDG_WM_BASE_INTERFACE: &[u8] = b"xdg_wm_base";
pub const WL_SEAT_INTERFACE: &[u8] = b"wl_seat";
pub const ZWLR_LAYER_SHELL_V1_INTERFACE: &[u8] = b"zwlr_layer_shell_v1";
pub const WP_FRACTIONAL_SCALE_MANAGER_V1_INTERFACE: &[u8] = b"wp_fractional_scale_manager_v1";

/// Next-object-ID allocator for server-created objects.
pub struct ObjectIdAlloc {
    next: u32,
}

impl ObjectIdAlloc {
    pub const fn new() -> Self {
        // Server-side IDs start at 0xFF000000 by convention.
        Self { next: 0xFF00_0001 }
    }

    pub fn alloc(&mut self) -> u32 {
        let id = self.next;
        self.next += 1;
        id
    }
}

// ---------------------------------------------------------------------------
// IPC <-> Wire protocol bridge
// ---------------------------------------------------------------------------

/// Extract raw Wayland wire bytes from an IPC message.
/// Returns the byte slice length, or 0 if this is not a wire message.
pub fn ipc_to_wire(msg: &IpcMsg, out: &mut [u8; IPC_DATA_MAX]) -> usize {
    let tag_lo = msg.tag & 0xFFFF;
    if tag_lo != WL_MSG_TAG {
        return 0;
    }
    let byte_count = ((msg.tag >> 16) & 0xFFFF) as usize;
    let n = byte_count.min(IPC_DATA_MAX);

    // Copy register data into contiguous byte buffer.
    // regs[0..7] are 8 u64 values = 64 bytes max.
    let src = &msg.regs as *const u64 as *const u8;
    unsafe {
        core::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), n);
    }
    n
}

/// Pack a Wayland event into an IPC reply message.
/// Returns the IPC message ready to send.
pub fn wire_to_ipc(event: &WlEvent) -> IpcMsg {
    let mut reply = IpcMsg::empty();
    let n = event.len.min(IPC_DATA_MAX);
    reply.tag = WL_MSG_TAG | ((n as u64) << 16);

    let dst = &mut reply.regs as *mut u64 as *mut u8;
    unsafe {
        core::ptr::copy_nonoverlapping(event.buf.as_ptr(), dst, n);
    }
    reply
}

/// Pack multiple events into a single IPC reply by concatenating their wire
/// bytes. If the total exceeds 64 bytes, only the events that fit are
/// included. Returns the IPC message.
pub fn events_to_ipc(events: &[WlEvent; MAX_EVENTS], count: usize) -> IpcMsg {
    let mut reply = IpcMsg::empty();
    let dst = &mut reply.regs as *mut u64 as *mut u8;
    let mut offset: usize = 0;

    for i in 0..count {
        let ev = &events[i];
        if offset + ev.len > IPC_DATA_MAX {
            break;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                ev.buf.as_ptr(),
                dst.add(offset),
                ev.len,
            );
        }
        offset += ev.len;
    }

    reply.tag = WL_MSG_TAG | ((offset as u64) << 16);
    reply
}

/// Build an IPC reply carrying the SHM pool handle for cross-process mapping.
/// The client receives this and calls shm_map() to map the shared pages.
pub fn shm_pool_reply(shm_handle: u64, page_count: u32, pool_id: u32) -> IpcMsg {
    let mut reply = IpcMsg::empty();
    reply.tag = WL_SHM_POOL_TAG;
    reply.regs[0] = shm_handle;
    reply.regs[1] = page_count as u64;
    reply.regs[2] = pool_id as u64;
    reply
}

// ---------------------------------------------------------------------------
// Object ID lookup types for dispatch
// ---------------------------------------------------------------------------

/// Maximum number of xdg_surface objects tracked per client.
pub const MAX_XDG_SURFACES: usize = 16;

/// Maximum number of xdg_toplevel objects tracked per client.
pub const MAX_XDG_TOPLEVELS: usize = 16;

/// Maximum number of wl_shm_pool objects tracked per client.
pub const MAX_SHM_POOLS: usize = 16;

/// An xdg_surface binding: maps client object ID to the associated wl_surface.
pub struct XdgSurfaceBinding {
    pub xdg_surface_id: u32,
    pub wl_surface_id: u32,
    pub active: bool,
}

impl XdgSurfaceBinding {
    pub const fn empty() -> Self {
        Self { xdg_surface_id: 0, wl_surface_id: 0, active: false }
    }
}

/// An xdg_toplevel binding.
pub struct XdgToplevelBinding {
    pub toplevel_id: u32,
    pub xdg_surface_id: u32,
    pub active: bool,
}

impl XdgToplevelBinding {
    pub const fn empty() -> Self {
        Self { toplevel_id: 0, xdg_surface_id: 0, active: false }
    }
}

/// Maximum fractional_scale object IDs tracked per client.
pub const MAX_CLIENT_FRACTIONAL_SCALES: usize = 16;

/// Per-client object ID tracking for dispatch.
pub struct ClientObjects {
    pub registry_id: u32,
    pub compositor_id: u32,
    pub shm_id: u32,
    pub xdg_wm_base_id: u32,
    pub seat_id: u32,
    pub pointer_id: u32,
    pub keyboard_id: u32,
    pub layer_shell_id: u32,
    pub fractional_scale_mgr_id: u32,
    pub xdg_surfaces: [XdgSurfaceBinding; MAX_XDG_SURFACES],
    pub xdg_toplevels: [XdgToplevelBinding; MAX_XDG_TOPLEVELS],
    pub shm_pool_ids: [u32; MAX_SHM_POOLS],
    /// Client-allocated `zwlr_layer_surface_v1` object IDs owned by
    /// this client. 0 = free slot. Tracked here so the dispatcher can
    /// route layer_surface opcodes back to the correct compositor pool
    /// entry.
    pub layer_surface_ids: [u32; layer_shell::MAX_LAYER_SURFACES],
    pub fractional_scale_ids: [u32; MAX_CLIENT_FRACTIONAL_SCALES],
}

impl ClientObjects {
    pub const fn empty() -> Self {
        Self {
            registry_id: 0,
            compositor_id: 0,
            shm_id: 0,
            xdg_wm_base_id: 0,
            seat_id: 0,
            pointer_id: 0,
            keyboard_id: 0,
            layer_shell_id: 0,
            fractional_scale_mgr_id: 0,
            xdg_surfaces: [const { XdgSurfaceBinding::empty() }; MAX_XDG_SURFACES],
            xdg_toplevels: [const { XdgToplevelBinding::empty() }; MAX_XDG_TOPLEVELS],
            shm_pool_ids: [0u32; MAX_SHM_POOLS],
            layer_surface_ids: [0u32; layer_shell::MAX_LAYER_SURFACES],
            fractional_scale_ids: [0u32; MAX_CLIENT_FRACTIONAL_SCALES],
        }
    }

    /// Track a new wp_fractional_scale_v1 object ID for this client.
    pub fn add_fractional_scale(&mut self, obj_id: u32) {
        for slot in &mut self.fractional_scale_ids {
            if *slot == 0 {
                *slot = obj_id;
                return;
            }
        }
    }

    /// Forget a wp_fractional_scale_v1 object ID (on destroy).
    pub fn remove_fractional_scale(&mut self, obj_id: u32) {
        for slot in &mut self.fractional_scale_ids {
            if *slot == obj_id {
                *slot = 0;
                return;
            }
        }
    }

    /// Is this ID a known wp_fractional_scale_v1?
    pub fn is_fractional_scale(&self, id: u32) -> bool {
        for &fid in &self.fractional_scale_ids {
            if fid != 0 && fid == id {
                return true;
            }
        }
        false
    }

    pub fn is_xdg_surface(&self, id: u32) -> bool {
        for xs in &self.xdg_surfaces {
            if xs.active && xs.xdg_surface_id == id {
                return true;
            }
        }
        false
    }

    pub fn is_xdg_toplevel(&self, id: u32) -> bool {
        for xt in &self.xdg_toplevels {
            if xt.active && xt.toplevel_id == id {
                return true;
            }
        }
        false
    }

    pub fn is_shm_pool(&self, id: u32) -> bool {
        for &pid in &self.shm_pool_ids {
            if pid != 0 && pid == id {
                return true;
            }
        }
        false
    }

    /// Register a new xdg_surface binding.
    pub fn add_xdg_surface(&mut self, xdg_id: u32, wl_surface_id: u32) {
        for xs in &mut self.xdg_surfaces {
            if !xs.active {
                xs.xdg_surface_id = xdg_id;
                xs.wl_surface_id = wl_surface_id;
                xs.active = true;
                return;
            }
        }
    }

    /// Register a new xdg_toplevel binding.
    pub fn add_xdg_toplevel(&mut self, toplevel_id: u32, xdg_surface_id: u32) {
        for xt in &mut self.xdg_toplevels {
            if !xt.active {
                xt.toplevel_id = toplevel_id;
                xt.xdg_surface_id = xdg_surface_id;
                xt.active = true;
                return;
            }
        }
    }

    /// Register a new shm pool ID.
    pub fn add_shm_pool(&mut self, pool_id: u32) {
        for slot in &mut self.shm_pool_ids {
            if *slot == 0 {
                *slot = pool_id;
                return;
            }
        }
    }

    /// Find the xdg_surface_id for a given toplevel.
    pub fn xdg_surface_for_toplevel(&self, toplevel_id: u32) -> u32 {
        for xt in &self.xdg_toplevels {
            if xt.active && xt.toplevel_id == toplevel_id {
                return xt.xdg_surface_id;
            }
        }
        0
    }

    /// Find the wl_surface_id for a given xdg_surface.
    pub fn wl_surface_for_xdg(&self, xdg_surface_id: u32) -> u32 {
        for xs in &self.xdg_surfaces {
            if xs.active && xs.xdg_surface_id == xdg_surface_id {
                return xs.wl_surface_id;
            }
        }
        0
    }

    /// Register a client-allocated `zwlr_layer_surface_v1` object ID.
    pub fn add_layer_surface(&mut self, object_id: u32) {
        for slot in &mut self.layer_surface_ids {
            if *slot == 0 {
                *slot = object_id;
                return;
            }
        }
    }

    /// Drop a `zwlr_layer_surface_v1` object ID on destroy.
    pub fn remove_layer_surface(&mut self, object_id: u32) {
        for slot in &mut self.layer_surface_ids {
            if *slot == object_id {
                *slot = 0;
                return;
            }
        }
    }

    /// Is this object ID a registered layer_surface for this client?
    pub fn is_layer_surface(&self, object_id: u32) -> bool {
        self.layer_surface_ids.iter().any(|&id| id != 0 && id == object_id)
    }
}

// ---------------------------------------------------------------------------
// Dispatch result
// ---------------------------------------------------------------------------

/// Result of dispatching a single Wayland message.
pub struct DispatchResult {
    pub events: [WlEvent; MAX_EVENTS],
    pub event_count: usize,
    /// If a new surface was created, its object ID.
    pub new_surface_id: u32,
    /// If a wl_surface::commit was received, the surface ID.
    pub committed_surface_id: u32,
    /// If a wl_surface::attach was received: (surface_id, buffer_id).
    pub attach: (u32, u32),
    /// If a toplevel was created, its info.
    pub new_toplevel: (u32, u32, u32), // (toplevel_id, xdg_surface_id, wl_surface_id)
    /// If set_title was received: (toplevel_id, title bytes, title len).
    pub title_update: (u32, [u8; 64], usize),
    /// Set if damage was reported on a surface.
    pub damage: bool,
    /// If a new SHM pool was created: (pool_id, size, fd/shm_hint). size=0 means no pool.
    /// The third element carries the fd from the client's create_pool request
    /// (used as an SHM handle hint if the client pre-created the SHM).
    pub new_pool: (u32, u32, i32),
    /// If a new SHM buffer was created: the buffer + pool_object_id. buffer_id=0 means none.
    pub new_buffer: (shm::ShmBuffer, u32),
    /// If a popup was born this round: parsed ids from xdg_surface::get_popup.
    pub new_popup: shell::PopupBirth,
    /// xdg_surface id whose get_popup spawned `new_popup` (0 if none).
    pub new_popup_xdg_surface: u32,
    /// object id of a popup whose destroy was dispatched (0 if none).
    pub popup_destroyed: u32,
    /// object id of a popup whose reposition was dispatched (0 if none).
    pub popup_repositioned: u32,
    /// If a new zwlr_layer_surface_v1 was created via get_layer_surface:
    /// (layer_surface_object_id, wl_surface_id, layer_as_u32). 0 means none.
    pub new_layer_surface: (u32, u32, u32),
    /// Set by layer_shell opcodes that change geometry (size, anchor,
    /// margin, exclusive_zone, destroy). Tells the compose loop to
    /// re-run `layer_shell::layout_all`.
    pub layer_layout_dirty: bool,
}

impl DispatchResult {
    pub const fn empty() -> Self {
        Self {
            events: [const { WlEvent::new() }; MAX_EVENTS],
            event_count: 0,
            new_surface_id: 0,
            committed_surface_id: 0,
            attach: (0, 0),
            new_toplevel: (0, 0, 0),
            title_update: (0, [0u8; 64], 0),
            damage: false,
            new_pool: (0, 0, -1),
            new_buffer: (shm::ShmBuffer::empty(), 0),
            new_popup: shell::PopupBirth { popup_id: 0, parent_xdg_surface: 0, positioner_id: 0 },
            new_popup_xdg_surface: 0,
            popup_destroyed: 0,
            popup_repositioned: 0,
            new_layer_surface: (0, 0, 0),
            layer_layout_dirty: false,
        }
    }
}

/// Dispatch a parsed Wayland message to the appropriate handler.
///
/// `msg`: the parsed message
/// `objs`: per-client object tracking (updated in place)
/// `configure_serial`: the next configure serial to use (incremented on use)
///
/// Returns a `DispatchResult` with events to send and state changes to apply.
pub fn dispatch_message(
    msg: &WlMessage,
    objs: &mut ClientObjects,
    configure_serial: &mut u32,
) -> DispatchResult {
    let mut result = DispatchResult::empty();
    let id = msg.object_id;

    // Route by object ID.

    // 1. wl_display (always object 1)
    if id == WL_DISPLAY_ID {
        let mut small_events: [WlEvent; 4] = [const { WlEvent::new() }; 4];
        let mut count = 0usize;
        display::handle_request(msg, &mut small_events, &mut count, &mut objs.registry_id);

        // If get_registry was called, also send global advertisements.
        if msg.opcode == 1 && objs.registry_id != 0 {
            registry::send_globals(
                objs.registry_id,
                &mut result.events,
                &mut result.event_count,
            );
        }

        // Copy display events (sync/delete_id) into result.
        for i in 0..count {
            if result.event_count < MAX_EVENTS {
                result.events[result.event_count] = WlEvent::new();
                let dst = &mut result.events[result.event_count];
                dst.buf[..small_events[i].len].copy_from_slice(
                    &small_events[i].buf[..small_events[i].len],
                );
                dst.len = small_events[i].len;
                result.event_count += 1;
            }
        }

        return result;
    }

    // 2. wl_registry (client's registry object)
    if id == objs.registry_id && objs.registry_id != 0 {
        if let Some(bound) = registry::handle_bind(msg) {
            // Track which global was bound and under which client ID.
            match bound.global_name {
                1 => {
                    objs.compositor_id = bound.client_id;
                }
                2 => {
                    objs.shm_id = bound.client_id;
                    // Send format advertisements when shm is bound.
                    shm::send_formats(
                        bound.client_id,
                        &mut result.events,
                        &mut result.event_count,
                    );
                }
                3 => {
                    objs.xdg_wm_base_id = bound.client_id;
                }
                4 => {
                    objs.seat_id = bound.client_id;
                    // Send seat capabilities when seat is bound.
                    seat::send_capabilities(
                        bound.client_id,
                        &mut result.events,
                        &mut result.event_count,
                    );
                }
                5 => {
                    objs.layer_shell_id = bound.client_id;
                }
                6 => {
                    // wp_fractional_scale_manager_v1 is a pure stub: no
                    // events are sent at bind time. The client will issue
                    // get_fractional_scale later.
                    objs.fractional_scale_mgr_id = bound.client_id;
                }
                _ => {}
            }
        }
        return result;
    }

    // 3. wl_compositor
    if id == objs.compositor_id && objs.compositor_id != 0 {
        if let Some(surface_id) = compositor::handle_request(msg) {
            result.new_surface_id = surface_id;
        }
        return result;
    }

    // 4. wl_shm
    if id == objs.shm_id && objs.shm_id != 0 {
        if let Some((pool_id, fd, size)) = shm::handle_create_pool(msg) {
            objs.add_shm_pool(pool_id);
            // Signal the caller to allocate pool memory.
            // fd carries the client's SHM handle hint (if client pre-created it).
            result.new_pool = (pool_id, size, fd);
        }
        return result;
    }

    // 5. wl_shm_pool (any registered pool ID)
    if objs.is_shm_pool(id) {
        if msg.opcode == 0 {
            // create_buffer: parse buffer params and signal the caller.
            if let Some(buf) = shm::handle_create_buffer(msg) {
                result.new_buffer = (buf, id); // id = pool object ID
            }
        }
        // opcode 1 = destroy, opcode 2 = resize: no events needed
        return result;
    }

    // 6. xdg_wm_base
    if id == objs.xdg_wm_base_id && objs.xdg_wm_base_id != 0 {
        // opcode 1 = create_positioner (handled separately so it never
        // flows into the get_xdg_surface path below).
        if msg.opcode == 1 {
            let _ = shell::handle_wm_base_create_positioner(msg);
            return result;
        }
        if let Some((xdg_surface_id, wl_surface_id)) = shell::handle_wm_base_request(msg) {
            objs.add_xdg_surface(xdg_surface_id, wl_surface_id);
        }
        return result;
    }

    // 6b. xdg_positioner (routed by object id against the positioner pool)
    if xdg_popup::find_positioner_by_object(id).is_some() {
        shell::handle_positioner_request(msg);
        return result;
    }

    // 7. xdg_surface
    if objs.is_xdg_surface(id) {
        // opcode 3 = get_popup — peel off before the toplevel path.
        if msg.opcode == 3 {
            if let Some(birth) = shell::handle_xdg_surface_get_popup(msg) {
                result.new_popup = birth;
                result.new_popup_xdg_surface = id;
            }
            return result;
        }
        if let Some(toplevel_id) = shell::handle_xdg_surface_request(msg) {
            let wl_surface_id = objs.wl_surface_for_xdg(id);
            objs.add_xdg_toplevel(toplevel_id, id);
            result.new_toplevel = (toplevel_id, id, wl_surface_id);

            // Send toplevel configure + xdg_surface configure.
            let serial = *configure_serial;
            *configure_serial += 1;

            shell::send_toplevel_configure(
                toplevel_id, 0, 0,
                &mut result.events, &mut result.event_count,
            );
            shell::send_configure(
                id, serial,
                &mut result.events, &mut result.event_count,
            );
        }
        return result;
    }

    // 7b. xdg_popup (routed by object id against the popup pool)
    if xdg_popup::find_popup_by_object(id).is_some() {
        shell::handle_popup_request(msg);
        if msg.opcode == 0 {
            result.popup_destroyed = id;
        } else if msg.opcode == 2 {
            result.popup_repositioned = id;
        }
        return result;
    }

    // 8. xdg_toplevel
    if objs.is_xdg_toplevel(id) {
        match msg.opcode {
            2 => {
                // set_title
                let (title_bytes, _consumed) = msg.arg_string(0);
                let len = title_bytes.len().min(64);
                let mut title_buf = [0u8; 64];
                title_buf[..len].copy_from_slice(&title_bytes[..len]);
                result.title_update = (id, title_buf, len);
            }
            _ => {
                // Other toplevel requests (set_parent, set_app_id, move, resize, etc.)
                // are stubs for now.
            }
        }
        return result;
    }

    // 9. wl_seat
    if id == objs.seat_id && objs.seat_id != 0 {
        if let Some((kind, obj_id)) = seat::handle_request(msg) {
            match kind {
                0 => objs.pointer_id = obj_id,
                1 => objs.keyboard_id = obj_id,
                _ => {}
            }
        }
        return result;
    }

    // 10. zwlr_layer_shell_v1
    if id == objs.layer_shell_id && objs.layer_shell_id != 0 {
        if let Some(gls) = layer_shell::handle_shell_request(msg) {
            if let Some(slot) = layer_shell::allocate() {
                if let Some(ls) = layer_shell::get_mut_by_slot(slot) {
                    ls.object_id = gls.object_id;
                    ls.surface_id = gls.surface_id;
                    ls.layer = gls.layer;
                }
                objs.add_layer_surface(gls.object_id);
                result.new_layer_surface = (gls.object_id, gls.surface_id, gls.layer.as_u32());
                result.layer_layout_dirty = true;

                // Send initial configure(serial, 0, 0) so the client
                // can ack and commit its first buffer.
                let serial = *configure_serial;
                *configure_serial += 1;
                layer_shell::send_configure(
                    gls.object_id,
                    serial,
                    0,
                    0,
                    &mut result.events,
                    &mut result.event_count,
                );
            }
        }
        return result;
    }

    // 11. wp_fractional_scale_manager_v1
    //   opcode 0 = destroy        (no-op; manager global stays bound)
    //   opcode 1 = get_fractional_scale(id: new_id, surface: object)
    if id == objs.fractional_scale_mgr_id && objs.fractional_scale_mgr_id != 0 {
        match msg.opcode {
            0 => { /* destroy: no-op */ }
            1 => {
                let new_id = msg.arg_u32(0);
                let surface_id = msg.arg_u32(4);
                if new_id != 0 {
                    let _ = fractional_scale::allocate(new_id, surface_id);
                    objs.add_fractional_scale(new_id);
                    fractional_scale::send_preferred_scale(
                        new_id,
                        fractional_scale::SCALE_120FIXED_1X,
                        &mut result.events,
                        &mut result.event_count,
                    );
                }
            }
            _ => {}
        }
        return result;
    }

    // 12. zwlr_layer_surface_v1 (client-allocated IDs)
    if objs.is_layer_surface(id) {
        let dirty = layer_shell::handle_surface_request(msg);
        if dirty {
            result.layer_layout_dirty = true;
            result.damage = true;
        }
        if msg.opcode == layer_shell::LAYER_SURFACE_DESTROY {
            objs.remove_layer_surface(id);
        }
        return result;
    }

    // 13. wp_fractional_scale_v1 (per-surface object)
    //   opcode 0 = destroy
    if objs.is_fractional_scale(id) {
        if msg.opcode == 0 {
            fractional_scale::destroy(id);
            objs.remove_fractional_scale(id);
        }
        return result;
    }

    // 14. wl_surface (client-allocated IDs, checked via surface existence)
    // wl_surface opcodes: 1=attach, 2=damage, 3=frame, 6=commit
    // These are identified by matching against known surface IDs in
    // the global SURFACES table. The caller checks this after dispatch
    // returns with unrecognized IDs.
    //
    // We handle common wl_surface opcodes here generically:
    match msg.opcode {
        1 => {
            // attach(buffer: object, x: int, y: int)
            let buffer_id = msg.arg_u32(0);
            result.attach = (id, buffer_id);
        }
        2 => {
            // damage(x, y, width, height) -- mark surface as damaged
            result.damage = true;
        }
        3 => {
            // frame(callback: new_id) -- request a frame callback
            let callback_id = msg.arg_u32(0);
            // Immediately send done (simplified; a real compositor would
            // delay until next vblank).
            if result.event_count < MAX_EVENTS {
                let mut ev = WlEvent::new();
                ev.begin(callback_id, 0); // wl_callback::done
                ev.put_u32(0);            // serial
                ev.finish();
                result.events[result.event_count] = ev;
                result.event_count += 1;
            }
            // delete_id
            if result.event_count < MAX_EVENTS {
                let mut del = WlEvent::new();
                del.begin(WL_DISPLAY_ID, 1); // wl_display::delete_id
                del.put_u32(callback_id);
                del.finish();
                result.events[result.event_count] = del;
                result.event_count += 1;
            }
        }
        6 => {
            // commit
            result.committed_surface_id = id;
        }
        _ => {}
    }

    result
}
