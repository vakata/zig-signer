const std = @import("std");
const asn1 = @import("../asn1.zig");
const Node = asn1.Node;
const Certificate = @import("Certificate.zig").Certificate;
const DateTime = @import("../helpers/DateTime.zig").DateTime;

pub const P7S = struct {
    allocator: std.mem.Allocator,
    node: *Node,

    pub fn init(allocator: std.mem.Allocator, cert: *Certificate, data: []const u8) !*P7S {
        const self = try allocator.create(P7S);
        const iss = try cert.issuer(allocator);
        defer allocator.free(iss);
        const ser = try cert.serial(allocator);
        defer allocator.free(ser);
        const utc = DateTime.init(std.time.milliTimestamp());
        const datetime = try allocator.alloc(u8, 13);
        defer allocator.free(datetime);
        _ = try std.fmt.bufPrint(
            datetime,
            "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z",
            .{ utc.year % 100, utc.month, utc.day, utc.hour, utc.minute, utc.second }
        );
        const p7s = try Node.fromChildren(allocator, .sequence, &[_]*Node{
            try Node.fromValue(allocator, .object_identifier, .{ .string = "1.2.840.113549.1.7.2" }),
            try Node.fromChildren(allocator, ._explicit0, &[_]*Node{ // signed data wrapper
                try Node.fromChildren(allocator, .sequence, &[_]*Node{
                    try Node.fromValue(allocator, .integer, .{ .int = 1 }),
                    try Node.fromChildren(allocator, .set, &[_]*Node{ // digest
                        try Node.fromChildren(allocator, .sequence, &[_]*Node{ // algo
                            try Node.fromValue(allocator, .object_identifier, .{ .string = "2.16.840.1.101.3.4.2.1" }),
                            try Node.fromValue(allocator, .null, .{ .null = {} }),
                        }),
                    }),
                    try Node.fromChildren(allocator, .sequence, &[_]*Node{ // encap info
                        try Node.fromValue(allocator, .object_identifier, .{ .string = "1.2.840.113549.1.7.1" }),
                    }),
                    try Node.fromValue(allocator, ._explicit0, .{ .string = cert.der[0..] }),
                    try Node.fromChildren(allocator, .set, &[_]*Node{ // signer infos
                        try Node.fromChildren(allocator, .sequence, &[_]*Node{ // signer info
                            try Node.fromValue(allocator, .integer, .{ .int = 1 }), // cms version
                            try Node.fromChildren(allocator, .sequence, &[_]*Node{ // issuer and serial
                                try Node.fromValue(allocator, .sequence, .{ .string = iss }),
                                try Node.fromValue(allocator, .integer, .{ .string = ser }),
                            }),
                            try Node.fromChildren(allocator, .sequence, &[_]*Node{ // algo
                                try Node.fromValue(allocator, .object_identifier, .{ .string = "2.16.840.1.101.3.4.2.1" }),
                                try Node.fromValue(allocator, .null, .{ .null = {} }),
                            }),
                            try Node.fromChildren(allocator, ._explicit0, &[_]*Node{ // signed attributes
                                try Node.fromChildren(allocator, .sequence, &[_]*Node{ // attribute 1 - content type
                                    try Node.fromValue(allocator, .object_identifier, .{ .string = "1.2.840.113549.1.9.3" }),
                                    try Node.fromChildren(allocator, .set, &[_]*Node{
                                        try Node.fromValue(allocator, .object_identifier, .{ .string = "1.2.840.113549.1.7.1" }),
                                    }),
                                }),
                                try Node.fromChildren(allocator, .sequence, &[_]*Node{ // attribute 2 - signing time
                                    try Node.fromValue(allocator, .object_identifier, .{ .string = "1.2.840.113549.1.9.5" }),
                                    try Node.fromChildren(allocator, .set, &[_]*Node{
                                        try Node.fromValue(allocator, .utc_time, .{ .string = datetime }),
                                    }),
                                }),
                                try Node.fromChildren(allocator, .sequence, &[_]*Node{ // attribute 3 - hash
                                    try Node.fromValue(allocator, .object_identifier, .{ .string = "1.2.840.113549.1.9.4" }),
                                    try Node.fromChildren(allocator, .set, &[_]*Node{
                                        try Node.fromValue (allocator, .octet_string, .{ .string = data }),
                                    }),
                                }),
                            }),
                            try Node.fromChildren(allocator, .sequence, &[_]*Node{ // signature algo
                            }),
                        }),
                    }),
                }),
            }),
        });
        var algo = p7s.child(1).child(0).child(4).child(0).child(4);
        if (cert.isRSA()) {
            try algo.nodes.append(try Node.fromValue(allocator, .object_identifier, .{ .string = "1.2.840.113549.1.1.11" }));
            try algo.nodes.append(try Node.fromValue(allocator, .null, .{ .null = {} }));
        } else {
            try algo.nodes.append(try Node.fromValue(allocator, .object_identifier, .{ .string = "1.2.840.10045.4.3.2" }));
        }
        self.* = .{
            .allocator = allocator,
            .node = p7s,
        };
        return self;
    }
    pub fn deinit(self: *P7S) void {
        self.node.deinit();
        self.allocator.destroy(self);
    }
    pub fn digest(self: *P7S, allocator: std.mem.Allocator) ![]const u8 {
        const signed = try asn1.encode(self.allocator, self.node.child(1).child(0).child(4).child(0).child(3));
        defer self.allocator.free(signed);
        var signed_cpy = try self.allocator.alloc(u8, signed.len);
        defer self.allocator.free(signed_cpy);
        @memcpy(signed_cpy, signed);
        signed_cpy[0] = 49;
        var signed_hash = try allocator.alloc(u8, 32);
        std.crypto.hash.sha2.Sha256.hash(signed_cpy[0..], signed_hash[0..32], .{});
        return signed_hash;
    }
    pub fn sign(self: *P7S, signature: []const u8) !void {
        try self.node.child(1).child(0).child(4).child(0).nodes.append(
            try Node.fromValue(self.allocator, .octet_string, .{ .string = signature })
        );
    }
    pub fn toString(self: *P7S, allocator: std.mem.Allocator) ![]const u8 {
        const der = try asn1.encode(self.allocator, self.node);
        defer self.allocator.free(der);
        const encoded = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(der.len));
        _ = std.base64.standard.Encoder.encode(encoded, der);
        return encoded;
    }
};
