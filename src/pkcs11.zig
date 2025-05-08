const std = @import("std");
const asn1 = @import("asn1.zig");
const Certificate = @import("Certificate.zig").Certificate;

pub const C = @cImport({
    @cInclude("pkcs11.h");
});

const SlotSess = struct { slot:c_ulong, sess:c_ulong };
const CertSess = struct { cert:u64, sess:c_ulong };

pub const Lib = struct {
    allocator: std.mem.Allocator,
    lib: std.DynLib,
    sym: *C.CK_FUNCTION_LIST,
    sessions: std.ArrayList(SlotSess),
    certificates: std.ArrayList(CertSess),

    pub fn init(allocator: std.mem.Allocator, path: []const u8) !*Lib {
        const self = try allocator.create(Lib);
        var lib = try std.DynLib.open(path);
        var sym: *C.CK_FUNCTION_LIST = undefined;
        const getFunctionList = lib.lookup(C.CK_C_GetFunctionList, "C_GetFunctionList").?.?;
        const rv = getFunctionList(@ptrCast(&sym));
        if (rv != C.CKR_OK) {
            return error.GeneralFailure;
        }
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
            return error.PKCS11Error;
        }
    }
    fn certSess(self: *Lib, cert: u64) !c_ulong {
        for (self.certificates.items[0..]) |entry| {
            if (cert == entry.cert) {
                return entry.sess;
            }
        }
        return error.UnknownCertificate;
    }
    fn sessCert(self: *Lib, sess: c_ulong) !u64 {
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
        var args: C.CK_C_INITIALIZE_ARGS = .{ .flags = C.CKF_OS_LOCKING_OK };
        try self.err(self.sym.C_Initialize.?(&args));
    }
    pub fn finalize(self: *Lib) !void {
        const args: C.CK_VOID_PTR = null;
        try self.err(self.sym.C_Finalize.?(args));
    }
    pub fn getSlots(self: *Lib, allocator: std.mem.Allocator, empty: bool) ![]u64 {
        var count: C.CK_ULONG = 0;
        const tokenPresent: C.CK_BBOOL = if (empty) C.CK_FALSE else C.CK_TRUE;
        try self.err(self.sym.C_GetSlotList.?(tokenPresent, null, &count));
        const slots = try allocator.alloc(C.CK_ULONG, count);
        try self.err(self.sym.C_GetSlotList.?(tokenPresent, slots.ptr, &count));
        return slots[0..count];
    }

    pub fn closeSessions(self: *Lib, slot_id: c_ulong) !void {
        try self.err(self.sym.C_CloseAllSessions.?(slot_id));
    }
    pub fn closeSession(self: *Lib, session: c_ulong) !void {
        try self.err(self.sym.C_CloseSession.?(session));
    }
    pub fn openSession(self: *Lib, slot_id: c_ulong) !c_ulong {
        var c_flags: c_ulong = 0;
        c_flags = c_flags | C.CKF_RW_SESSION;
        c_flags = c_flags | C.CKF_SERIAL_SESSION;
        var handle: c_ulong = 0;
        try self.err(self.sym.C_OpenSession.?(slot_id, c_flags, null, null, &handle));
        try self.sessions.append(.{ .slot = slot_id, .sess = handle });
        return handle;
    }
    pub fn findCertificates(self: *Lib, session: c_ulong) !void {
        const template = [_]C.CK_ATTRIBUTE{
            C.CK_ATTRIBUTE{ .type = C.CKA_CLASS, .pValue = @constCast(&C.CKO_CERTIFICATE), .ulValueLen = @sizeOf(u64) },
        };
        try self.err(self.sym.C_FindObjectsInit.?(session, @constCast(&template), 1));

        defer _ = self.sym.C_FindObjectsFinal.?(session);
        while (true) {
            var obj: u64 = 0;
            var count: C.CK_ULONG = 0;
            const rv = self.sym.C_FindObjects.?(session, &obj, 1, &count);
            if (rv != C.CKR_OK or count == 0) break;
            try self.certificates.append(.{ .cert = obj, .sess = session });
        }
    }
    pub fn login(self: *Lib, session: c_ulong, pin: []const u8) !void {
        try self.err(self.sym.C_Login.?(session, C.CKU_USER, @constCast(pin.ptr), pin.len));
    }
    pub fn getPrivateKey(self: *Lib, cert: c_ulong) !u64 {
        const attr_type = C.CKA_ID;
        var attr = C.CK_ATTRIBUTE{
            .type = attr_type,
            .pValue = null,
            .ulValueLen = 0,
        };

        const session = try self.certSess(cert);
        try self.err(self.sym.C_GetAttributeValue.?(session, cert, &attr, 1));
        const buf = try self.allocator.alloc(u8, attr.ulValueLen);
        defer self.allocator.free(buf);

        attr.pValue = buf.ptr;
        try self.err(self.sym.C_GetAttributeValue.?(session, cert, &attr, 1));

        const template = [_]C.CK_ATTRIBUTE{
            C.CK_ATTRIBUTE{ .type = C.CKA_CLASS, .pValue = @constCast(&C.CKO_PRIVATE_KEY), .ulValueLen = @sizeOf(u64) },
            C.CK_ATTRIBUTE{ .type = C.CKA_ID, .pValue = buf.ptr, .ulValueLen = buf.len },
        };
        try self.err(self.sym.C_FindObjectsInit.?(session, @constCast(&template), template.len));
        defer _ = self.sym.C_FindObjectsFinal.?(session);

        var object: u64 = undefined;
        var count: C.CK_ULONG = 0;
        try self.err(self.sym.C_FindObjects.?(session, &object, 1, &count));
        if (count == 0) {
            return error.GeneralFailure;
        }
        return object;
    }

    pub fn getCertificate(self: *Lib, allocator: std.mem.Allocator, cert: u64) ![]u8 {
        const session = try self.certSess(cert);

        const attr_type = C.CKA_VALUE;
        var attr = C.CK_ATTRIBUTE{
            .type = attr_type,
            .pValue = null,
            .ulValueLen = 0,
        };
        try self.err(self.sym.C_GetAttributeValue.?(session, cert, &attr, 1));
        const buf = try allocator.alloc(u8, attr.ulValueLen);
        errdefer allocator.free(buf);
        attr.pValue = buf.ptr;
        try self.err(self.sym.C_GetAttributeValue.?(session, cert, &attr, 1));

        return buf[0..];
    }
    pub fn signHashWithCertificate(self: *Lib, allocator: std.mem.Allocator, cert: u64, pin: []const u8, hash: []const u8) ![]const u8 {
        const sess = try self.certSess(cert);
        const slot = try self.sessSlot(sess);
        try self.login(sess, pin);
        const priv = try self.getPrivateKey(cert);
        return self.signHash(allocator, slot, sess, priv, hash);
    }
    pub fn signHash(self: *Lib, allocator: std.mem.Allocator, slot: c_ulong, session: c_ulong, privkey: u64, hash: []const u8) ![]const u8 {
        var mech_count: C.CK_ULONG = undefined;
        try self.err(self.sym.C_GetMechanismList.?(slot, null, &mech_count));
        const mech_list = try allocator.alloc(c_ulong, mech_count);
        defer allocator.free(mech_list);

        try self.err(self.sym.C_GetMechanismList.?(slot, @ptrCast(mech_list.ptr), &mech_count));

        const attr_type = C.CKA_KEY_TYPE;
        var attr = C.CK_ATTRIBUTE{
            .type = attr_type,
            .pValue = null,
            .ulValueLen = 0,
        };
        var buf: u64 = 0;
        attr.pValue = @constCast(&buf);
        try self.err(self.sym.C_GetAttributeValue.?(session, privkey, &attr, 1));

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

        const prefix = "\x30\x31\x30\x0D\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20";
        var hash_len: u64 = hash.len;
        if (selected == C.CKM_RSA_PKCS) {
            hash_len += prefix.len;
        }
        const norm_hash = try allocator.alloc(u8, hash_len);
        defer allocator.free(norm_hash);
        if (selected == C.CKM_RSA_PKCS) {
            @memcpy(norm_hash[0..prefix.len], prefix);
            @memcpy(norm_hash[prefix.len..], hash);
        } else {
            @memcpy(norm_hash, hash);
        }

        const mechanism = C.CK_MECHANISM{ .mechanism = selected, .pParameter = null, .ulParameterLen = 0 };
        try self.err(self.sym.C_SignInit.?(session, @constCast(&mechanism), privkey));
        var siglen: c_ulong = 0;
        try self.err(self.sym.C_Sign.?(session, norm_hash.ptr, norm_hash.len, null, &siglen));
        const sig = try allocator.alloc(u8, siglen);
        errdefer allocator.free(sig);
        try self.err(self.sym.C_Sign.?(session, norm_hash.ptr, norm_hash.len, sig.ptr, &siglen));
        if (selected == C.CKM_RSA_PKCS) {
            return sig;
        }
        const rs = sig[0..32];
        const ss = sig[32..];
        const sigseq = try asn1.Node.fromChildren(allocator, .sequence, &[_]*asn1.Node{
            try asn1.Node.init(allocator, .integer, rs, null),
            try asn1.Node.init(allocator, .integer, ss, null),
        });
        defer sigseq.deinit();
        return try asn1.encode(allocator, sigseq);
    }
    pub fn getCertificates(self: *Lib, allocator: std.mem.Allocator, certificates: *std.ArrayList(*Certificate)) void {
        // collect slots
        const slots = self.getSlots(self.allocator, false) catch { return; };
        defer self.allocator.free(slots);
        
        // open a session for each slot and collect certicates
        for (slots) |slot| {
            const session = self.openSession(slot) catch { continue; };
            self.findCertificates(session) catch { continue; };
            for (self.certificates.items[0..]) |entry| {
                if (Certificate.init(allocator, self, entry.cert) catch null) |certificate| {
                    certificates.append(certificate) catch {};
                }
            }
        }
    }
};

