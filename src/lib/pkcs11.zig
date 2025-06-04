const std = @import("std");

pub const C = @cImport({
    @cInclude("pkcs11.h");
});

pub const CK_VERSION = extern struct {
    major: u8,
    minor: u8,
};
pub const CK_FUNCTION_LIST = extern struct {
    version: CK_VERSION,
};
const C_GetFunctionList = *const fn (**CK_FUNCTION_LIST) callconv(.C) C.CK_RV;

const C_Initialize = *const fn (*C.CK_VOID_PTR) callconv(.C) C.CK_RV;
const C_Finalize = *const fn (*C.CK_VOID_PTR) callconv(.C) C.CK_RV;
const C_GetSlotList = *const fn (C.CK_BBOOL, ?[*]C.CK_SLOT_ID, *C.CK_ULONG) callconv(.C) C.CK_RV;
const C_GetMechanismList = *const fn (C.CK_SLOT_ID, ?*C.CK_MECHANISM_TYPE, *C.CK_ULONG) callconv(.C) C.CK_RV;
const C_OpenSession = *const fn (C.CK_SLOT_ID, C.CK_FLAGS, C.CK_VOID_PTR, C.CK_NOTIFY, *C.CK_SESSION_HANDLE) callconv(.C) C.CK_RV;
const C_CloseSession = *const fn (C.CK_SESSION_HANDLE) callconv(.C) C.CK_RV;
const C_CloseAllSessions = *const fn (C.CK_SLOT_ID) callconv(.C) C.CK_RV;
const C_GetSessionInfo = *const fn (C.CK_SESSION_HANDLE, *C.CK_SESSION_INFO) callconv(.C) C.CK_RV;
const C_Login = *const fn (C.CK_SESSION_HANDLE, C.CK_USER_TYPE, [*]const C.CK_UTF8CHAR, C.CK_ULONG) callconv(.C) C.CK_RV;
const C_Logout = *const fn (C.CK_SESSION_HANDLE) callconv(.C) C.CK_RV;
const C_GetAttributeValue = *const fn (C.CK_SESSION_HANDLE, C.CK_OBJECT_HANDLE, *C.CK_ATTRIBUTE, C.CK_ULONG) callconv(.C) C.CK_RV;
const C_FindObjectsInit = *const fn (C.CK_SESSION_HANDLE, [*]const C.CK_ATTRIBUTE, C.CK_ULONG) callconv(.C) C.CK_RV;
const C_FindObjects = *const fn (C.CK_SESSION_HANDLE, *C.CK_OBJECT_HANDLE, C.CK_ULONG, *C.CK_ULONG) callconv(.C) C.CK_RV;
const C_FindObjectsFinal = *const fn (C.CK_SESSION_HANDLE) callconv(.C) C.CK_RV;
const C_SignInit = *const fn (C.CK_SESSION_HANDLE, *const C.CK_MECHANISM, C.CK_OBJECT_HANDLE) callconv(.C) C.CK_RV;
const C_Sign = *const fn (C.CK_SESSION_HANDLE, [*]const C.CK_BYTE, C.CK_ULONG, ?[*]C.CK_BYTE, *C.CK_ULONG) callconv(.C) C.CK_RV;

const FuncList = struct {
    C_Initialize: C_Initialize,
    C_Finalize: C_Finalize,
    C_GetSlotList: C_GetSlotList,
    C_GetMechanismList: C_GetMechanismList,
    C_OpenSession: C_OpenSession,
    C_CloseSession: C_CloseSession,
    C_CloseAllSessions: C_CloseAllSessions,
    C_GetSessionInfo: C_GetSessionInfo,
    C_Login: C_Login,
    C_Logout: C_Logout,
    C_GetAttributeValue: C_GetAttributeValue,
    C_FindObjectsInit: C_FindObjectsInit,
    C_FindObjects: C_FindObjects,
    C_FindObjectsFinal: C_FindObjectsFinal,
    C_SignInit: C_SignInit,
    C_Sign: C_Sign,
};

// TODO: remove those in favour of a single struct and group c functions at the top
const SlotSess = struct { slot:c_ulong, sess:c_ulong };
const CertSess = struct { cert:c_ulong, sess:c_ulong };

pub const Lib = struct {
    allocator: std.mem.Allocator,
    lib: std.DynLib,
    sym: FuncList,
    sessions: std.ArrayList(SlotSess),
    certificates: std.ArrayList(CertSess),

    pub fn init(allocator: std.mem.Allocator, path: []const u8) !*Lib {
        std.debug.print(" ? init starting ... {s}\n", .{path});
        const self = try allocator.create(Lib);
        var lib = try std.DynLib.open(path);
        std.debug.print(" ? lib opened ... {s}\n", .{path});

        const info = lib.lookup(C_GetFunctionList, "C_GetFunctionList") orelse return error.BindError;
        var list: *CK_FUNCTION_LIST = undefined;
        try self.err(info(&list));
        std.debug.print(" ? PKCS#11 version: {}.{}\n", .{list.version.major, list.version.minor});

        const sym: FuncList = .{
            .C_Initialize = lib.lookup(C_Initialize, "C_Initialize") orelse return error.BindError,
            .C_Finalize = lib.lookup(C_Finalize, "C_Finalize") orelse return error.BindError,
            .C_GetSlotList = lib.lookup(C_GetSlotList, "C_GetSlotList") orelse return error.BindError,
            .C_GetMechanismList = lib.lookup(C_GetMechanismList, "C_GetMechanismList") orelse return error.BindError,
            .C_OpenSession = lib.lookup(C_OpenSession, "C_OpenSession") orelse return error.BindError,
            .C_CloseSession = lib.lookup(C_CloseSession, "C_CloseSession") orelse return error.BindError,
            .C_CloseAllSessions = lib.lookup(C_CloseAllSessions, "C_CloseAllSessions") orelse return error.BindError,
            .C_GetSessionInfo = lib.lookup(C_GetSessionInfo, "C_GetSessionInfo") orelse return error.BindError,
            .C_Login = lib.lookup(C_Login, "C_Login") orelse return error.BindError,
            .C_Logout = lib.lookup(C_Logout, "C_Logout") orelse return error.BindError,
            .C_GetAttributeValue = lib.lookup(C_GetAttributeValue, "C_GetAttributeValue") orelse return error.BindError,
            .C_FindObjectsInit = lib.lookup(C_FindObjectsInit, "C_FindObjectsInit") orelse return error.BindError,
            .C_FindObjects = lib.lookup(C_FindObjects, "C_FindObjects") orelse return error.BindError,
            .C_FindObjectsFinal = lib.lookup(C_FindObjectsFinal, "C_FindObjectsFinal") orelse return error.BindError,
            .C_SignInit = lib.lookup(C_SignInit, "C_SignInit") orelse return error.BindError,
            .C_Sign = lib.lookup(C_Sign, "C_Sign") orelse return error.BindError,
        };
        const sessions = std.ArrayList(SlotSess).init(allocator);
        const certificates = std.ArrayList(CertSess).init(allocator);
        self.* = .{ .allocator = allocator, .lib = lib, .sym = sym, .sessions = sessions, .certificates = certificates };
        try self.initialize();
        return self;
    }
    pub fn deinit(self: *Lib) void {
        for (self.sessions.items[0..]) |entry| {
            self.closeSession(entry.sess) catch {};
        }
        self.sessions.deinit();
        self.certificates.deinit();
        self.finalize() catch {};
        self.lib.close();
        self.allocator.destroy(self);
    }

    fn err(_: *Lib, rv: c_ulong) !void {
        if (rv != C.CKR_OK) {
            std.debug.print(" ? lib error: {d}\n", .{rv});
            return error.PKCS11Error;
        }
    }
    fn certSess(self: *Lib, cert: c_ulong) !c_ulong {
        for (self.certificates.items[0..]) |entry| {
            if (cert == entry.cert) {
                return entry.sess;
            }
        }
        return error.UnknownCertificate;
    }
    fn sessCert(self: *Lib, sess: c_ulong) !c_ulong {
        for (self.certificates.items[0..]) |entry| {
            if (sess == entry.sess) {
                return entry.cert;
            }
        }
        return error.unknownSession;
    }
    fn sessSlot(self: *Lib, sess: c_ulong) !c_ulong {
        for (self.sessions.items[0..]) |entry| {
            if (sess == entry.sess) {
                return entry.slot;
            }
        }
        return error.unknownSession;
    }
    fn slotSess(self: *Lib, slot: c_ulong) !c_ulong {
        for (self.sessions.items[0..]) |entry| {
            if (slot == entry.slot) {
                return entry.sess;
            }
        }
        return error.unknownSlot;
    }

    pub fn initialize(self: *Lib) !void {
        std.debug.print(" ? initialize\n", .{});
        var args: C.CK_VOID_PTR = null;
        try self.err(self.sym.C_Initialize(&args));
    }
    pub fn finalize(self: *Lib) !void {
        std.debug.print(" ? finalize\n", .{});
        var args: C.CK_VOID_PTR = null;
        try self.err(self.sym.C_Finalize(&args));
    }
    pub fn getSlots(self: *Lib, allocator: std.mem.Allocator, empty: bool) ![]C.CK_SLOT_ID {
        std.debug.print(" ? slots\n", .{});
        var count: C.CK_ULONG = 0;
        const tokenPresent: C.CK_BBOOL = if (empty) C.CK_FALSE else C.CK_TRUE;
        try self.err(self.sym.C_GetSlotList(tokenPresent, null, &count));
        const slots = try allocator.alloc(C.CK_SLOT_ID, count);
        try self.err(self.sym.C_GetSlotList(tokenPresent, slots.ptr, &count));
        return slots[0..count];
    }

    pub fn closeSessions(self: *Lib, slot_id: c_ulong) !void {
        std.debug.print(" ? close sessions {d}\n", .{slot_id});
        try self.err(self.sym.C_CloseAllSessions(slot_id));
    }
    pub fn closeSession(self: *Lib, session: c_ulong) !void {
        std.debug.print(" ? close session: {d}\n", .{session});
        try self.err(self.sym.C_CloseSession(session));
    }
    pub fn openSession(self: *Lib, slot_id: C.CK_SLOT_ID) !C.CK_SESSION_HANDLE {
        var c_flags: C.CK_FLAGS = 0;
        c_flags = c_flags | C.CKF_RW_SESSION;
        c_flags = c_flags | C.CKF_SERIAL_SESSION;
        var s: C.CK_SESSION_HANDLE = 0;
        const p: C.CK_SESSION_HANDLE_PTR = &s;
        const a: C.CK_VOID_PTR = null;
        const n: C.CK_NOTIFY = null;
        std.debug.print(" ? open session with slot {d} and flags {d}\n", .{slot_id, c_flags});
        try self.err(self.sym.C_OpenSession(slot_id, c_flags, a, n, p));
        try self.sessions.append(.{ .slot = slot_id, .sess = s });
        return s;
    }
    pub fn findCertificates(self: *Lib) !void {
        std.debug.print(" ? find certicates\n", .{});
        // collect slots
        const slots = self.getSlots(self.allocator, false) catch { return; };
        defer self.allocator.free(slots);
        
        // open a session for each slot and collect certicates
        for (slots) |slot| {
            std.debug.print("   - slot {d}\n", .{slot});
            const session = self.openSession(slot) catch { continue; };
            const template = [_]C.CK_ATTRIBUTE{
                C.CK_ATTRIBUTE{ .type = C.CKA_CLASS, .pValue = @constCast(&C.CKO_CERTIFICATE), .ulValueLen = @sizeOf(c_ulong) },
            };
            try self.err(self.sym.C_FindObjectsInit(session, @constCast(&template), 1));

            defer _ = self.sym.C_FindObjectsFinal(session);
            while (true) {
                var obj: c_ulong = 0;
                var count: C.CK_ULONG = 0;
                const rv = self.sym.C_FindObjects(session, &obj, 1, &count);
                if (rv != C.CKR_OK or count == 0) break;
                std.debug.print("   - found {d}\n", .{obj});
                try self.certificates.append(.{ .cert = obj, .sess = session });
            }
        }
    }
    pub fn login(self: *Lib, session: c_ulong, pin: []const u8) !void {
        std.debug.print(" ? login\n", .{});
        try self.err(self.sym.C_Login(session, C.CKU_USER, @constCast(pin.ptr), @intCast(pin.len)));
    }
    pub fn getPrivateKey(self: *Lib, cert: c_ulong) !c_ulong {
        std.debug.print(" ? private\n", .{});
        const attr_type = C.CKA_ID;
        var attr = C.CK_ATTRIBUTE{
            .type = attr_type,
            .pValue = null,
            .ulValueLen = 0,
        };

        const session = try self.certSess(cert);
        try self.err(self.sym.C_GetAttributeValue(session, cert, &attr, 1));
        const buf = try self.allocator.alloc(u8, attr.ulValueLen);
        defer self.allocator.free(buf);

        attr.pValue = buf.ptr;
        try self.err(self.sym.C_GetAttributeValue(session, cert, &attr, 1));

        const template = [_]C.CK_ATTRIBUTE{
            C.CK_ATTRIBUTE{ .type = C.CKA_CLASS, .pValue = @constCast(&C.CKO_PRIVATE_KEY), .ulValueLen = @sizeOf(c_ulong) },
            C.CK_ATTRIBUTE{ .type = C.CKA_ID, .pValue = buf.ptr, .ulValueLen = @intCast(buf.len) },
        };
        try self.err(self.sym.C_FindObjectsInit(session, @constCast(&template), @intCast(template.len)));
        defer _ = self.sym.C_FindObjectsFinal(session);

        var object: c_ulong = undefined;
        var count: C.CK_ULONG = 0;
        try self.err(self.sym.C_FindObjects(session, &object, 1, &count));
        if (count == 0) {
            return error.GeneralFailure;
        }
        return object;
    }

    pub fn getCertificate(self: *Lib, allocator: std.mem.Allocator, cert: c_ulong) ![]const u8 {
        std.debug.print(" ? certificate\n", .{});
        const session = try self.certSess(cert);
        const attr_type = C.CKA_VALUE;
        var attr = C.CK_ATTRIBUTE{
            .type = attr_type,
            .pValue = null,
            .ulValueLen = 0,
        };
        try self.err(self.sym.C_GetAttributeValue(session, cert, &attr, 1));
        const buf = try allocator.alloc(u8, attr.ulValueLen);
        errdefer allocator.free(buf);
        attr.pValue = buf.ptr;
        try self.err(self.sym.C_GetAttributeValue(session, cert, &attr, 1));
        return buf[0..];
    }
    pub fn sign(self: *Lib, allocator: std.mem.Allocator, cert: c_ulong, pin: []const u8, data: []const u8) ![]const u8 {
        std.debug.print(" ? sign\n", .{});
        const session = try self.certSess(cert);
        const slot = try self.sessSlot(session);

        const info: *C.CK_SESSION_INFO = try allocator.create(C.CK_SESSION_INFO);
        defer allocator.destroy(info);
        try self.err(self.sym.C_GetSessionInfo(session, info));
        if (info.state > 2) {
            self.err(self.sym.C_Logout(session)) catch {};
        }

        try self.login(session, pin);
        const privkey = try self.getPrivateKey(cert);

        var mech_count: C.CK_ULONG = undefined;
        try self.err(self.sym.C_GetMechanismList(slot, null, &mech_count));
        const mech_list = try allocator.alloc(c_ulong, mech_count);
        defer allocator.free(mech_list);

        try self.err(self.sym.C_GetMechanismList(slot, @ptrCast(mech_list.ptr), &mech_count));

        const attr_type = C.CKA_KEY_TYPE;
        var attr = C.CK_ATTRIBUTE{
            .type = attr_type,
            .pValue = null,
            .ulValueLen = 0,
        };
        var buf: c_ulong = 0;
        attr.pValue = @constCast(&buf);
        try self.err(self.sym.C_GetAttributeValue(session, privkey, &attr, 1));

        var preferred = std.ArrayList(c_ulong).init(allocator);
        defer preferred.deinit();
        if (buf == 0) {
            try preferred.append(C.CKM_RSA_PKCS);
        }
        if (buf == 3) {
            try preferred.append(C.CKM_ECDSA);
        }
        var selected: c_ulong = 0;
        outer: for (preferred.items[0..]) |preferred_mech| {
            for (mech_list[0..]) |supported| {
                if (supported == preferred_mech) {
                    selected = preferred_mech;
                    break :outer;
                }
            }
        }
        if (selected == 0) {
            return error.GeneralFailure;
        }

        const mechanism = C.CK_MECHANISM{ .mechanism = selected, .pParameter = null, .ulParameterLen = 0 };
        try self.err(self.sym.C_SignInit(session, @constCast(&mechanism), privkey));
        var siglen: c_ulong = 0;
        try self.err(self.sym.C_Sign(session, @constCast(data.ptr), @intCast(data.len), null, &siglen));
        const sig = try allocator.alloc(u8, siglen);
        errdefer allocator.free(sig);
        try self.err(self.sym.C_Sign(session, @constCast(data.ptr), @intCast(data.len), sig.ptr, &siglen));
        return sig;
    }
};

