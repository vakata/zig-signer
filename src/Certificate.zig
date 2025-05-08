const std = @import("std");
const asn1 = @import("asn1.zig");
const Lib = @import("pkcs11.zig").Lib;
const DateTime = @import("Datetime.zig").DateTime;
const Node = asn1.Node;

pub const Certificate = struct {
    allocator: std.mem.Allocator,
    crt: u64,
    lib: *Lib,
    der: []u8,

    pub fn init(allocator: std.mem.Allocator, lib: *Lib, crt: u64) !*Certificate {
        const self = try allocator.create(Certificate);
        self.* = .{
            .allocator = allocator,
            .crt = crt,
            .lib = lib,
            .der = try lib.getCertificate(allocator, crt)
        };
        return self;
    }
    pub fn deinit(self: *Certificate) void {
        self.allocator.free(self.der);
        self.allocator.destroy(self);
    }
 
    pub fn signDetached(self: *Certificate, allocator: std.mem.Allocator, hash: []const u8, pin: []const u8) ![]const u8 {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();
        const iss = try self.issuer(arena_allocator);
        defer arena_allocator.free(iss);
        const ser = try self.serial(arena_allocator, true);
        defer arena_allocator.free(ser);
        const utc = DateTime.init(std.time.milliTimestamp());
        var datetime: [13]u8 = undefined;
        _ = try std.fmt.bufPrint(
            &datetime,
            "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z",
            .{ utc.year % 100, utc.month, utc.day, utc.hour, utc.minute, utc.second }
        );
        const p7s = try Node.fromChildren(arena_allocator, .sequence, &[_]*Node{
            try Node.fromValue(arena_allocator, .object_identifier, .{ .string = "1.2.840.113549.1.7.2" }),
            try Node.fromChildren(arena_allocator, ._explicit0, &[_]*Node{ // signed data wrapper
                try Node.fromChildren(arena_allocator, .sequence, &[_]*Node{
                    try Node.fromValue(arena_allocator, .integer, .{ .int = 1 }),
                    try Node.fromChildren(arena_allocator, .set, &[_]*Node{ // digest
                        try Node.fromChildren(arena_allocator, .sequence, &[_]*Node{ // algo
                            try Node.fromValue(arena_allocator, .object_identifier, .{ .string = "2.16.840.1.101.3.4.2.1" }),
                            try Node.fromValue(arena_allocator, .null, .{ .null = {} }),
                        }),
                    }),
                    try Node.fromChildren(arena_allocator, .sequence, &[_]*Node{ // encap info
                        try Node.fromValue(arena_allocator, .object_identifier, .{ .string = "1.2.840.113549.1.7.1" }),
                    }),
                    try Node.init(arena_allocator, ._explicit0, self.der[0..], null),
                    try Node.fromChildren(arena_allocator, .set, &[_]*Node{ // signer infos
                        try Node.fromChildren(arena_allocator, .sequence, &[_]*Node{ // signer info
                            try Node.fromValue(arena_allocator, .integer, .{ .int = 1 }), // cms version
                            try Node.fromChildren(arena_allocator, .sequence, &[_]*Node{ // issuer and serial
                                try Node.init(arena_allocator, .sequence, iss, null),
                                try Node.init(arena_allocator, .integer, ser, null),
                            }),
                            try Node.fromChildren(arena_allocator, .sequence, &[_]*Node{ // algo
                                try Node.fromValue(arena_allocator, .object_identifier, .{ .string = "2.16.840.1.101.3.4.2.1" }),
                                try Node.fromValue(arena_allocator, .null, .{ .null = {} }),
                            }),
                            try Node.fromChildren(arena_allocator, ._explicit0, &[_]*Node{ // signed attributes
                                try Node.fromChildren(arena_allocator, .sequence, &[_]*Node{ // attribute 1 - content type
                                    try Node.fromValue(arena_allocator, .object_identifier, .{ .string = "1.2.840.113549.1.9.3" }),
                                    try Node.fromChildren(arena_allocator, .set, &[_]*Node{
                                        try Node.fromValue(arena_allocator, .object_identifier, .{ .string = "1.2.840.113549.1.7.1" }),
                                    }),
                                }),
                                try Node.fromChildren(arena_allocator, .sequence, &[_]*Node{ // attribute 2 - signing time
                                    try Node.fromValue(arena_allocator, .object_identifier, .{ .string = "1.2.840.113549.1.9.5" }),
                                    try Node.fromChildren(arena_allocator, .set, &[_]*Node{
                                        try Node.init(arena_allocator, .utc_time, &datetime, null),
                                    }),
                                }),
                                try Node.fromChildren(arena_allocator, .sequence, &[_]*Node{ // attribute 3 - hash
                                    try Node.fromValue(arena_allocator, .object_identifier, .{ .string = "1.2.840.113549.1.9.4" }),
                                    try Node.fromChildren(arena_allocator, .set, &[_]*Node{
                                        try Node.init(arena_allocator, .octet_string, hash, null),
                                    }),
                                }),
                            }),
                            try Node.fromChildren(arena_allocator, .sequence, &[_]*Node{ // signature algo
                            }),
                        }),
                    }),
                }),
            }),
        });
        defer p7s.deinit();

        var algo = p7s.child(1).child(0).child(4).child(0).child(4);
        if (self.rsa()) {
            try algo.nodes.append(try Node.fromValue(arena_allocator, .object_identifier, .{ .string = "1.2.840.113549.1.1.11" }));
            try algo.nodes.append(try Node.fromValue(arena_allocator, .null, .{ .null = {} }));
        } else {
            try algo.nodes.append(try asn1.Node.fromValue(arena_allocator, .object_identifier, .{ .string = "1.2.840.10045.4.3.2" }));
        }
        
        const signed = try asn1.encode(arena_allocator, p7s.child(1).child(0).child(4).child(0).child(3));
        defer arena_allocator.free(signed);
        var signed_cpy = try arena_allocator.alloc(u8, signed.len);
        defer arena_allocator.free(signed_cpy);
        @memcpy(signed_cpy, signed);
        signed_cpy[0] = 49;
        var signed_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(signed_cpy[0..], &signed_hash, .{});
        const signature = try self.lib.signHashWithCertificate(arena_allocator, self.crt, pin, &signed_hash);
        defer arena_allocator.free(signature);
        
        try p7s.child(1).child(0).child(4).child(0).nodes.append(
            try asn1.Node.init(arena_allocator, .octet_string, signature, null)
        );

        const der = try asn1.encode(arena_allocator, p7s);
        defer arena_allocator.free(der);
        const encoded = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(der.len));
        _ = std.base64.standard.Encoder.encode(encoded, der);
        return encoded;
    }
    pub fn ecdsa(self: *Certificate) bool {
        return std.mem.indexOf(u8, self.der, "\x2A\x86\x48\xCE\x3D\x02\x01") != null;
    }
    pub fn rsa(self: *Certificate) bool {
        return std.mem.indexOf(u8, self.der, "\x2A\x86\x48\xCE\x3D\x02\x01") == null;
    }
    pub fn serial(self: *Certificate, allocator: std.mem.Allocator, raw: bool) ![]const u8 {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();
        const nodes = try asn1.decode(arena_allocator, self.der[0..]);
        defer {
            for (nodes) |node| { node.deinit(); }
            arena_allocator.free(nodes);
        }
        const node = nodes[0].child(0).child(1);
        const number = node.val[0..];
        if (raw) {
            return try allocator.dupe(u8, number);
        }
        const hexbuf = try allocator.alloc(u8, number.len * 2);
        return try std.fmt.bufPrint(hexbuf, "{s}", .{std.fmt.fmtSliceHexUpper(number)});
    }
    pub fn issuer(self: *Certificate, allocator: std.mem.Allocator) ![]const u8 {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();
        const nodes = try asn1.decode(arena_allocator, self.der[0..]);
        defer {
            for (nodes) |node| { node.deinit(); }
            arena_allocator.free(nodes);
        }
        const val = nodes[0].child(0).child(3).val;
        const cpy = try allocator.alloc(u8, val.len);
        @memcpy(cpy, val);
        return cpy;
    }
    pub fn name(self: *Certificate, allocator: std.mem.Allocator) ![]const u8 {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();
        const nodes = try asn1.decode(arena_allocator, self.der[0..]);
        defer {
            for (nodes) |node| { node.deinit(); }
            arena_allocator.free(nodes);
        }
        var names = std.ArrayList([]const u8).init(allocator);
        defer names.deinit();
        try names.append(try self.serial(allocator, false));
        for (nodes[0].child(0).child(5).children()) |node| {
            try names.append(node.child(0).child(1).val);
        }
        return try std.mem.join(allocator, " / ", names.items);
    }
};

