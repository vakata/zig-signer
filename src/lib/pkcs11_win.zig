const std = @import("std");

pub const CK_VERSION = extern struct {
    major: u8,
    minor: u8,
};
pub const CK_INFO = extern struct {
    cryptokiVersion: CK_VERSION,
    manufacturerID: [32]u8,
    flags: c_ulong,
    libraryDescription: [32]u8,
    libraryVersion: CK_VERSION,
};
pub const CK_SLOT_INFO = extern struct {
    slotDescription: [64]u8,
    manufacturerID: [32]u8,
    flags: c_ulong,
    hardwareVersion: CK_VERSION,
    firmwareVersion: CK_VERSION,
};
pub const CK_TOKEN_INFO = extern struct {
    label: [32]u8,
    manufacturerID: [32]u8,
    model: [16]u8,
    serialNumber: [16]u8,
    flags: c_ulong,
    ulMaxSessionCount: c_ulong,
    ulSessionCount: c_ulong,
    ulMaxRwSessionCount: c_ulong,
    ulRwSessionCount: c_ulong,
    ulMaxPinLen: c_ulong,
    ulMinPinLen: c_ulong,
    ulTotalPublicMemory: c_ulong,
    ulFreePublicMemory: c_ulong,
    ulTotalPrivateMemory: c_ulong,
    ulFreePrivateMemory: c_ulong,
    hardwareVersion: CK_VERSION,
    firmwareVersion: CK_VERSION,
    utcTime: [16]u8,
};
pub const CK_SESSION_INFO = extern struct {
    slotID: c_ulong,
    state: c_ulong,
    flags: c_ulong,
    ulDeviceError: c_ulong,
};
pub const CK_ATTRIBUTE = extern struct {
    type: c_ulong,
    pValue: ?*anyopaque,
    ulValueLen: c_ulong,
};
pub const CK_MECHANISM = extern struct {
    mechanism: c_ulong,
    pParameter: ?*anyopaque,
    ulParameterLen: c_ulong,
};
pub const CK_MECHANISM_INFO = extern struct {
    ulMinKeySize: c_ulong,
    ulMaxKeySize: c_ulong,
    flags: c_ulong,
};
pub const CK_NOTIFY = ?*const fn (c_ulong, c_ulong, ?*anyopaque) callconv(.C) c_ulong;

const CK_FUNCTION_LIST_PTR = [*c]CK_FUNCTION_LIST;
const CK_FUNCTION_LIST_PTR_PTR = [*c]CK_FUNCTION_LIST_PTR;

const C_Initialize = ?*const fn (?*anyopaque) callconv(.C) c_ulong;
const C_Finalize = ?*const fn (?*anyopaque) callconv(.C) c_ulong;
const C_GetInfo = ?*const fn (*CK_INFO) callconv(.C) c_ulong;
const C_GetFunctionList = ?*const fn (CK_FUNCTION_LIST_PTR_PTR) callconv(.C) c_ulong;
const C_GetSlotList = ?*const fn (u8, [*c]c_ulong, *c_ulong) callconv(.C) c_ulong;
const C_GetSlotInfo = ?*const fn (c_ulong, *CK_SLOT_INFO) callconv(.C) c_ulong;
const C_GetTokenInfo = ?*const fn (c_ulong, *CK_TOKEN_INFO) callconv(.C) c_ulong;
const C_GetMechanismList = ?*const fn (c_ulong, [*c]c_ulong, *c_ulong) callconv(.C) c_ulong;
const C_GetMechanismInfo = ?*const fn (c_ulong, c_ulong, *CK_MECHANISM_INFO) callconv(.C) c_ulong;
const C_InitToken = ?*const fn (c_ulong, [*c]u8, c_ulong, [*c]u8) callconv(.C) c_ulong;
const C_InitPIN = ?*const fn (c_ulong, [*c]u8, c_ulong) callconv(.C) c_ulong;
const C_SetPIN = ?*const fn (c_ulong, [*c]u8, c_ulong, [*c]u8, c_ulong) callconv(.C) c_ulong;
const C_OpenSession = ?*const fn (c_ulong, c_ulong, ?*anyopaque, CK_NOTIFY, *c_ulong) callconv(.C) c_ulong;
const C_CloseSession = ?*const fn (c_ulong) callconv(.C) c_ulong;
const C_CloseAllSessions = ?*const fn (c_ulong) callconv(.C) c_ulong;
const C_GetSessionInfo = ?*const fn (c_ulong, *CK_SESSION_INFO) callconv(.C) c_ulong;
const C_GetOperationState = ?*const fn (c_ulong, [*c]u8, [*c]c_ulong) callconv(.C) c_ulong;
const C_SetOperationState = ?*const fn (c_ulong, [*c]u8, c_ulong, c_ulong, c_ulong) callconv(.C) c_ulong;
const C_Login = ?*const fn (c_ulong, c_ulong, [*c]u8, c_ulong) callconv(.C) c_ulong;
const C_Logout = ?*const fn (c_ulong) callconv(.C) c_ulong;
const C_CreateObject = ?*const fn (c_ulong, [*c]CK_ATTRIBUTE, c_ulong, [*c]c_ulong) callconv(.C) c_ulong;
const C_CopyObject = ?*const fn (c_ulong, c_ulong, [*c]CK_ATTRIBUTE, c_ulong, [*c]c_ulong) callconv(.C) c_ulong;
const C_DestroyObject = ?*const fn (c_ulong, c_ulong) callconv(.C) c_ulong;
const C_GetObjectSize = ?*const fn (c_ulong, c_ulong, [*c]c_ulong) callconv(.C) c_ulong;
const C_GetAttributeValue = ?*const fn (c_ulong, c_ulong, [*c]CK_ATTRIBUTE, c_ulong) callconv(.C) c_ulong;
const C_SetAttributeValue = ?*const fn (c_ulong, c_ulong, [*c]CK_ATTRIBUTE, c_ulong) callconv(.C) c_ulong;
const C_FindObjectsInit = ?*const fn (c_ulong, [*c]CK_ATTRIBUTE, c_ulong) callconv(.C) c_ulong;
const C_FindObjects = ?*const fn (c_ulong, [*c]c_ulong, c_ulong, [*c]c_ulong) callconv(.C) c_ulong;
const C_FindObjectsFinal = ?*const fn (c_ulong) callconv(.C) c_ulong;
const C_EncryptInit = ?*const fn (c_ulong, [*c]CK_MECHANISM, c_ulong) callconv(.C) c_ulong;
const C_Encrypt = ?*const fn (c_ulong, [*c]u8, c_ulong, [*c]u8, [*c]c_ulong) callconv(.C) c_ulong;
const C_EncryptUpdate = ?*const fn (c_ulong, [*c]u8, c_ulong, [*c]u8, [*c]c_ulong) callconv(.C) c_ulong;
const C_EncryptFinal = ?*const fn (c_ulong, [*c]u8, [*c]c_ulong) callconv(.C) c_ulong;
const C_DecryptInit = ?*const fn (c_ulong, [*c]CK_MECHANISM, c_ulong) callconv(.C) c_ulong;
const C_Decrypt = ?*const fn (c_ulong, [*c]u8, c_ulong, [*c]u8, [*c]c_ulong) callconv(.C) c_ulong;
const C_DecryptUpdate = ?*const fn (c_ulong, [*c]u8, c_ulong, [*c]u8, [*c]c_ulong) callconv(.C) c_ulong;
const C_DecryptFinal = ?*const fn (c_ulong, [*c]u8, [*c]c_ulong) callconv(.C) c_ulong;
const C_DigestInit = ?*const fn (c_ulong, [*c]CK_MECHANISM) callconv(.C) c_ulong;
const C_Digest = ?*const fn (c_ulong, [*c]u8, c_ulong, [*c]u8, [*c]c_ulong) callconv(.C) c_ulong;
const C_DigestUpdate = ?*const fn (c_ulong, [*c]u8, c_ulong) callconv(.C) c_ulong;
const C_DigestKey = ?*const fn (c_ulong, c_ulong) callconv(.C) c_ulong;
const C_DigestFinal = ?*const fn (c_ulong, [*c]u8, [*c]c_ulong) callconv(.C) c_ulong;
const C_SignInit = ?*const fn (c_ulong, [*c]CK_MECHANISM, c_ulong) callconv(.C) c_ulong;
const C_Sign = ?*const fn (c_ulong, [*c]u8, c_ulong, [*c]u8, [*c]c_ulong) callconv(.C) c_ulong;
const C_SignUpdate = ?*const fn (c_ulong, [*c]u8, c_ulong) callconv(.C) c_ulong;
const C_SignFinal = ?*const fn (c_ulong, [*c]u8, [*c]c_ulong) callconv(.C) c_ulong;
const C_SignRecoverInit = ?*const fn (c_ulong, [*c]CK_MECHANISM, c_ulong) callconv(.C) c_ulong;
const C_SignRecover = ?*const fn (c_ulong, [*c]u8, c_ulong, [*c]u8, [*c]c_ulong) callconv(.C) c_ulong;
const C_VerifyInit = ?*const fn (c_ulong, [*c]CK_MECHANISM, c_ulong) callconv(.C) c_ulong;
const C_Verify = ?*const fn (c_ulong, [*c]u8, c_ulong, [*c]u8, c_ulong) callconv(.C) c_ulong;
const C_VerifyUpdate = ?*const fn (c_ulong, [*c]u8, c_ulong) callconv(.C) c_ulong;
const C_VerifyFinal = ?*const fn (c_ulong, [*c]u8, c_ulong) callconv(.C) c_ulong;
const C_VerifyRecoverInit = ?*const fn (c_ulong, [*c]CK_MECHANISM, c_ulong) callconv(.C) c_ulong;
const C_VerifyRecover = ?*const fn (c_ulong, [*c]u8, c_ulong, [*c]u8, [*c]c_ulong) callconv(.C) c_ulong;
const C_DigestEncryptUpdate = ?*const fn (c_ulong, [*c]u8, c_ulong, [*c]u8, [*c]c_ulong) callconv(.C) c_ulong;
const C_DecryptDigestUpdate = ?*const fn (c_ulong, [*c]u8, c_ulong, [*c]u8, [*c]c_ulong) callconv(.C) c_ulong;
const C_SignEncryptUpdate = ?*const fn (c_ulong, [*c]u8, c_ulong, [*c]u8, [*c]c_ulong) callconv(.C) c_ulong;
const C_DecryptVerifyUpdate = ?*const fn (c_ulong, [*c]u8, c_ulong, [*c]u8, [*c]c_ulong) callconv(.C) c_ulong;
const C_GenerateKey = ?*const fn (c_ulong, [*c]CK_MECHANISM, [*]CK_ATTRIBUTE, c_ulong, [*c]c_ulong) callconv(.C) c_ulong;
const C_GenerateKeyPair = ?*const fn (c_ulong, [*c]CK_MECHANISM, [*]CK_ATTRIBUTE, c_ulong, [*]CK_ATTRIBUTE, c_ulong, [*c]c_ulong, [*c]c_ulong) callconv(.C) c_ulong;
const C_WrapKey = ?*const fn (c_ulong, [*c]CK_MECHANISM, c_ulong, c_ulong, [*c]u8, [*c]c_ulong) callconv(.C) c_ulong;
const C_UnwrapKey = ?*const fn (c_ulong, [*c]CK_MECHANISM, c_ulong, [*c]u8, c_ulong, [*]CK_ATTRIBUTE, c_ulong, [*c]c_ulong) callconv(.C) c_ulong;
const C_DeriveKey = ?*const fn (c_ulong, [*c]CK_MECHANISM, c_ulong, [*]CK_ATTRIBUTE, c_ulong, [*c]c_ulong) callconv(.C) c_ulong;
const C_SeedRandom = ?*const fn (c_ulong, [*c]u8, c_ulong) callconv(.C) c_ulong;
const C_GenerateRandom = ?*const fn (c_ulong, [*c]u8, c_ulong) callconv(.C) c_ulong;
const C_GetFunctionStatus = ?*const fn (c_ulong) callconv(.C) c_ulong;
const C_CancelFunction = ?*const fn (c_ulong) callconv(.C) c_ulong;
const C_WaitForSlotEvent = ?*const fn (c_ulong, [*c]c_ulong, ?*anyopaque) callconv(.C) c_ulong;

pub const CK_FUNCTION_LIST = extern struct {
    version: CK_VERSION,
    C_Initialize: C_Initialize,
    C_Finalize: C_Finalize,
    C_GetInfo: C_GetInfo,
    C_GetFunctionList: C_GetFunctionList,
    C_GetSlotList: C_GetSlotList,
    C_GetSlotInfo: C_GetSlotInfo,
    C_GetTokenInfo: C_GetTokenInfo,
    C_GetMechanismList: C_GetMechanismList,
    C_GetMechanismInfo: C_GetMechanismInfo,
    C_InitToken: C_InitToken,
    C_InitPIN: C_InitPIN,
    C_SetPIN: C_SetPIN,
    C_OpenSession: C_OpenSession,
    C_CloseSession: C_CloseSession,
    C_CloseAllSessions: C_CloseAllSessions,
    C_GetSessionInfo: C_GetSessionInfo,
    C_GetOperationState: C_GetOperationState,
    C_SetOperationState: C_SetOperationState,
    C_Login: C_Login,
    C_Logout: C_Logout,
    C_CreateObject: C_CreateObject,
    C_CopyObject: C_CopyObject,
    C_DestroyObject: C_DestroyObject,
    C_GetObjectSize: C_GetObjectSize,
    C_GetAttributeValue: C_GetAttributeValue,
    C_SetAttributeValue: C_SetAttributeValue,
    C_FindObjectsInit: C_FindObjectsInit,
    C_FindObjects: C_FindObjects,
    C_FindObjectsFinal: C_FindObjectsFinal,
    C_EncryptInit: C_EncryptInit,
    C_Encrypt: C_Encrypt,
    C_EncryptUpdate: C_EncryptUpdate,
    C_EncryptFinal: C_EncryptFinal,
    C_DecryptInit: C_DecryptInit,
    C_Decrypt: C_Decrypt,
    C_DecryptUpdate: C_DecryptUpdate,
    C_DecryptFinal: C_DecryptFinal,
    C_DigestInit: C_DigestInit,
    C_Digest: C_Digest,
    C_DigestUpdate: C_DigestUpdate,
    C_DigestKey: C_DigestKey,
    C_DigestFinal: C_DigestFinal,
    C_SignInit: C_SignInit,
    C_Sign: C_Sign,
    C_SignUpdate: C_SignUpdate,
    C_SignFinal: C_SignFinal,
    C_SignRecoverInit: C_SignRecoverInit,
    C_SignRecover: C_SignRecover,
    C_VerifyInit: C_VerifyInit,
    C_Verify: C_Verify,
    C_VerifyUpdate: C_VerifyUpdate,
    C_VerifyFinal: C_VerifyFinal,
    C_VerifyRecoverInit: C_VerifyRecoverInit,
    C_VerifyRecover: C_VerifyRecover,
    C_DigestEncryptUpdate: C_DigestEncryptUpdate,
    C_DecryptDigestUpdate: C_DecryptDigestUpdate,
    C_SignEncryptUpdate: C_SignEncryptUpdate,
    C_DecryptVerifyUpdate: C_DecryptVerifyUpdate,
    C_GenerateKey: C_GenerateKey,
    C_GenerateKeyPair: C_GenerateKeyPair,
    C_WrapKey: C_WrapKey,
    C_UnwrapKey: C_UnwrapKey,
    C_DeriveKey: C_DeriveKey,
    C_SeedRandom: C_SeedRandom,
    C_GenerateRandom: C_GenerateRandom,
    C_GetFunctionStatus: C_GetFunctionStatus,
    C_CancelFunction: C_CancelFunction,
    C_WaitForSlotEvent: C_WaitForSlotEvent,
};

// TODO: remove those in favour of a single struct and group c functions at the top
const SlotSess = struct { slot:c_ulong, sess:c_ulong };
const CertSess = struct { cert:c_ulong, sess:c_ulong };

pub const Lib = struct {
    allocator: std.mem.Allocator,
    lib: std.DynLib,
    sym: *CK_FUNCTION_LIST,
    sessions: std.ArrayList(SlotSess),
    certificates: std.ArrayList(CertSess),

    pub fn init(allocator: std.mem.Allocator, path: []const u8) !*Lib {
        std.debug.print(" ? init starting ... {s}\n", .{path});
        const self = try allocator.create(Lib);
        var lib = try std.DynLib.open(path);
        std.debug.print(" ? lib opened ... {s}\n", .{path});

        const list = lib.lookup(C_GetFunctionList, "C_GetFunctionList") orelse return error.BindError;
        var sym: CK_FUNCTION_LIST_PTR = undefined;
        try self.err(list.?(&sym));

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
        if (rv != 0) {
            std.debug.print(" ? lib error: {x}\n", .{rv});
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
        const args: ?*anyopaque = null;
        try self.err(self.sym.C_Initialize.?(args));
    }
    pub fn finalize(self: *Lib) !void {
        std.debug.print(" ? finalize\n", .{});
        const args: ?*anyopaque = null;
        try self.err(self.sym.C_Finalize.?(args));
    }
    pub fn getSlots(self: *Lib, allocator: std.mem.Allocator, empty: bool) ![]c_ulong {
        std.debug.print(" ? getting slots ...\n", .{});
        var count: c_ulong = 0;
        const tokenPresent: u8 = if (empty) 0 else 1;
        try self.err(self.sym.C_GetSlotList.?(tokenPresent, null, &count));
        std.debug.print(" ? found {d} slots\n", .{count});
        const slots = try allocator.alloc(c_ulong, count);
        try self.err(self.sym.C_GetSlotList.?(tokenPresent, slots.ptr, &count));
        std.debug.print(" ? slots: {any}\n", .{slots});
        return slots[0..count];
    }

    pub fn closeSessions(self: *Lib, slot_id: c_ulong) !void {
        std.debug.print(" ? close sessions {d}\n", .{slot_id});
        try self.err(self.sym.C_CloseAllSessions.?(slot_id));
    }
    pub fn closeSession(self: *Lib, session: c_ulong) !void {
        std.debug.print(" ? close session: {d}\n", .{session});
        try self.err(self.sym.C_CloseSession.?(session));
    }
    pub fn openSession(self: *Lib, slot_id: c_ulong) !c_ulong {
        var c_flags: c_ulong = 0;
        c_flags = c_flags | 2; // r/w
        c_flags = c_flags | 4; // serial
        var s: c_ulong = 0;
        std.debug.print(" ? open session with slot {d} and flags {d}\n", .{slot_id, c_flags});
        try self.err(self.sym.C_OpenSession.?(slot_id, c_flags, null, null, &s));
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

            const si = try self.allocator.create(CK_SLOT_INFO);
            defer self.allocator.destroy(si);
            try self.err(self.sym.C_GetSlotInfo.?(slot, si));
            std.debug.print("     {s} {s}\n", .{si.manufacturerID, si.slotDescription});
            const ti = try self.allocator.create(CK_TOKEN_INFO);
            defer self.allocator.destroy(ti);
            try self.err(self.sym.C_GetTokenInfo.?(slot, ti));
            std.debug.print("     {s} {s}\n", .{ti.manufacturerID, ti.label});

            const session = self.openSession(slot) catch { continue; };
            const t: c_ulong = 0;
            var v: c_ulong = 0x00000001;
            const template = [_]CK_ATTRIBUTE{
                CK_ATTRIBUTE{ .type = t, .pValue = @constCast(&v), .ulValueLen = @sizeOf(c_ulong) },
            };
            try self.err(self.sym.C_FindObjectsInit.?(session, @constCast(&template), 1));

            defer _ = self.sym.C_FindObjectsFinal.?(session);
            while (true) {
                var obj: c_ulong = 0;
                var count: c_ulong = 0;
                const rv = self.sym.C_FindObjects.?(session, &obj, 1, &count);
                if (rv != 0 or count == 0) break;
                std.debug.print("   - found {d}\n", .{obj});
                try self.certificates.append(.{ .cert = obj, .sess = session });
            }
        }
    }
    pub fn login(self: *Lib, session: c_ulong, pin: []const u8) !void {
        std.debug.print(" ? login\n", .{});
        try self.err(self.sym.C_Login.?(session, 1, @constCast(pin.ptr), @intCast(pin.len)));
    }
    pub fn getPrivateKey(self: *Lib, cert: c_ulong) !c_ulong {
        std.debug.print(" ? private\n", .{});
        const cka_id: c_ulong = 0x00000102;
        var attr = [_]CK_ATTRIBUTE{
            CK_ATTRIBUTE{
                .type = cka_id,
                .pValue = null,
                .ulValueLen = 0,
            }
        };

        const session = try self.certSess(cert);
        try self.err(self.sym.C_GetAttributeValue.?(session, cert, &attr, 1));
        const buf = try self.allocator.alloc(u8, attr[0].ulValueLen);
        defer self.allocator.free(buf);

        attr[0].pValue = buf.ptr;
        try self.err(self.sym.C_GetAttributeValue.?(session, cert, &attr, 1));

        const cka_class: c_ulong = 0x00000000;
        const cko_private_key: c_ulong = 0x00000003;
        var template = [_]CK_ATTRIBUTE{
            CK_ATTRIBUTE{ .type = cka_class, .pValue = @constCast(&cko_private_key), .ulValueLen = @sizeOf(c_ulong) },
            CK_ATTRIBUTE{ .type = cka_id, .pValue = buf.ptr, .ulValueLen = @intCast(buf.len) },
        };
        try self.err(self.sym.C_FindObjectsInit.?(session, &template, @intCast(template.len)));
        defer _ = self.sym.C_FindObjectsFinal.?(session);

        var object: c_ulong = undefined;
        var count: c_ulong = 0;
        try self.err(self.sym.C_FindObjects.?(session, &object, 1, &count));
        if (count == 0) {
            return error.GeneralFailure;
        }
        return object;
    }

    pub fn getCertificate(self: *Lib, allocator: std.mem.Allocator, cert: c_ulong) ![]const u8 {
        std.debug.print(" ? certificate\n", .{});
        const session = try self.certSess(cert);
        const attr_type = 0x00000011;
        var attr = [_]CK_ATTRIBUTE{
            CK_ATTRIBUTE{
                .type = attr_type,
                .pValue = null,
                .ulValueLen = 0,
            }
        };
        try self.err(self.sym.C_GetAttributeValue.?(session, cert, &attr, 1));
        const buf = try allocator.alloc(u8, attr[0].ulValueLen);
        errdefer allocator.free(buf);
        attr[0].pValue = buf.ptr;
        try self.err(self.sym.C_GetAttributeValue.?(session, cert, &attr, 1));
        return buf[0..];
    }
    pub fn sign(self: *Lib, allocator: std.mem.Allocator, cert: c_ulong, pin: []const u8, data: []const u8) ![]const u8 {
        std.debug.print(" ? sign\n", .{});
        const session = try self.certSess(cert);
        const slot = try self.sessSlot(session);

        const info: *CK_SESSION_INFO = try allocator.create(CK_SESSION_INFO);
        defer allocator.destroy(info);
        try self.err(self.sym.C_GetSessionInfo.?(session, info));
        if (info.*.state > 2) {
            self.err(self.sym.C_Logout.?(session)) catch {};
        }

        try self.login(session, pin);
        const privkey = try self.getPrivateKey(cert);

        var mech_count: c_ulong = undefined;
        try self.err(self.sym.C_GetMechanismList.?(slot, null, &mech_count));
        const mech_list = try allocator.alloc(c_ulong, mech_count);
        defer allocator.free(mech_list);

        try self.err(self.sym.C_GetMechanismList.?(slot, @ptrCast(mech_list.ptr), &mech_count));

        const t: c_ulong = 0x00000100;
        var attr = [_]CK_ATTRIBUTE{
            CK_ATTRIBUTE{
                .type = t,
                .pValue = null,
                .ulValueLen = 0,
            }
        };
        var buf: c_ulong = 0;
        attr[0].pValue = @constCast(&buf);
        try self.err(self.sym.C_GetAttributeValue.?(session, privkey, &attr, 1));

        var preferred = std.ArrayList(c_ulong).init(allocator);
        defer preferred.deinit();
        if (buf == 0) {
            try preferred.append(0x00000001); // rsa
        }
        if (buf == 3) {
            try preferred.append(0x00001041); // ecdsa
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

        const mechanism = CK_MECHANISM{ .mechanism = selected, .pParameter = null, .ulParameterLen = 0 };
        try self.err(self.sym.C_SignInit.?(session, @constCast(&mechanism), privkey));
        var siglen: c_ulong = 0;
        try self.err(self.sym.C_Sign.?(session, @constCast(data.ptr), @intCast(data.len), null, &siglen));
        const sig = try allocator.alloc(u8, siglen);
        errdefer allocator.free(sig);
        try self.err(self.sym.C_Sign.?(session, @constCast(data.ptr), @intCast(data.len), sig.ptr, &siglen));
        return sig;
    }
};

