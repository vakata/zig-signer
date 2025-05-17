const std = @import("std");
const asn1 = @import("../asn1.zig");
const Node = asn1.Node;

pub const Certificate = struct {
    allocator: std.mem.Allocator,
    der: []const u8,
    nodes: std.ArrayList(*Node),

    pub fn init(allocator: std.mem.Allocator, der: []const u8) !*Certificate {
        const self = try allocator.create(Certificate);
        self.* = .{
            .allocator = allocator,
            .der = der,
            .nodes = try asn1.decode(allocator, der[0..])
        };
        return self;
    }
    pub fn deinit(self: *Certificate) void {
        for (self.nodes.items) |node| { node.deinit(); }
        self.nodes.deinit();
        self.allocator.destroy(self);
    }
    pub fn isECDSA(self: *Certificate) bool {
        // TODO: check subject public key info - algorithm id - rsa: 1.2.840.113549.1.1.1 
        return std.mem.indexOf(u8, self.der, "\x2A\x86\x48\xCE\x3D\x02\x01") != null;
    }
    pub fn isRSA(self: *Certificate) bool {
        // TODO: check subject public key info - algorithm id - rsa: 1.2.840.113549.1.1.1 
        return std.mem.indexOf(u8, self.der, "\x2A\x86\x48\xCE\x3D\x02\x01") == null;
    }
    pub fn serial(self: *Certificate, allocator: std.mem.Allocator) ![]const u8 {
        const node = self.nodes.items[0].child(0).child(1);
        const number = node.val[0..];
        return try allocator.dupe(u8, number);
    }
    pub fn serialHex(self: *Certificate, allocator: std.mem.Allocator) ![]const u8 {
        const number = try self.serial(allocator);
        defer allocator.free(number);
        const hexbuf = try allocator.alloc(u8, number.len * 2);
        return try std.fmt.bufPrint(hexbuf, "{s}", .{std.fmt.fmtSliceHexUpper(number)});
    }
    pub fn name(self: *Certificate, allocator: std.mem.Allocator) ![]const u8 {
        var names = std.ArrayList([]const u8).init(allocator);
        defer names.deinit();
        const ser = try self.serialHex(allocator);
        defer allocator.free(ser);
        try names.append(ser);
        for (self.nodes.items[0].child(0).child(5).children()) |node| {
            try names.append(node.child(0).child(1).val);
        }
        return try std.mem.join(allocator, " / ", names.items);
    }
    pub fn issuer(self: *Certificate, allocator: std.mem.Allocator) ![]const u8 {
        const val = self.nodes.items[0].child(0).child(3).val;
        const cpy = try allocator.alloc(u8, val.len);
        @memcpy(cpy, val);
        return cpy;
    }
};

test {
    std.testing.refAllDecls(@This());
}
