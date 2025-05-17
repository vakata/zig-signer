const std = @import("std");
const builtin = @import("builtin");
const pkcs11 = @import("lib/pkcs11.zig").Lib;
const asn1 = @import("asn1/asn1.zig");
const Node = asn1.Node;
const Certificate = @import("asn1/structures/Certificate.zig").Certificate;
const P7S = @import("asn1/structures/P7S.zig").P7S;
const webui = @import("webui");
const CertificateList = struct { lib: u64, handle: u64, name: []const u8 };

// global state - pin and chosen certificate that get populated by webui
var p: [8]u8 = [_]u8{0} ** 8;
var c: u8 = 0;
// global state - instances and found certificates
var instances: std.ArrayList(*pkcs11) = undefined;
var certificates: std.ArrayList(CertificateList) = undefined;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    // init globals
    instances = std.ArrayList(*pkcs11).init(allocator);
    defer {
        for (instances.items) |instance| {
            instance.deinit();
        }
        instances.deinit();
    }
    certificates = std.ArrayList(CertificateList).init(allocator);
    defer {
        for (certificates.items) |certificate| {
            allocator.free(certificate.name);
        }
        certificates.deinit();
    }

    scan(allocator) catch {};
    pick(allocator) catch {};
    _ = signData(allocator, "SAMPLE") catch null;
}

fn scan(allocator: std.mem.Allocator) !void {
    // libs default locations per OS
    const libs: []const []const u8 = comptime switch (builtin.target.os.tag) {
        .macos => &.{
            "/Library/Frameworks/eToken.framework/Versions/A/libIDPrimePKCS11.dylib"
        },
        .windows => &.{},
        .linux => &.{},
        else => .{}
    };
    // remove and discard all old instances
    for (instances.items) |instance| {
        instance.deinit();
    }
    instances.clearRetainingCapacity();
    // scan all available libs
    // TODO: provide an option for a hardcoded lib using a file
    for (libs) |lib| {
        if (pkcs11.init(allocator, lib) catch null) |instance| {
            instances.append(instance) catch {};
            instance.findCertificates() catch {};
        }
    }
    // clear all certificates
    for (certificates.items) |certificate| {
        allocator.free(certificate.name);
    }
    certificates.clearRetainingCapacity();
    // scan all instances for certificates
    for (0.., instances.items) |i, instance| {
        for (0.., instance.certificates.items) |j, certificate| {
            const der = instance.getCertificate(allocator, certificate.cert) catch { continue; };
            defer allocator.free(der);
            const cer = Certificate.init(allocator, der) catch { continue; };
            defer cer.deinit();
            try certificates.append(.{
                .lib = i,
                .handle = j,
                .name = cer.name(allocator) catch ""
            });
        }
    }
}
fn pick(allocator: std.mem.Allocator) !void {
    var certs = std.ArrayList(struct { handle: u64, name: []const u8 }).init(allocator);
    defer certs.deinit();
    for (0.., certificates.items) |i, certificate| {
        try certs.append(.{
            .handle = i,
            .name = certificate.name
        });
    }

    c = 0;
    p = [_]u8{0} ** 8;

    if (!builtin.is_test) {
        var window = webui.newWindow();
        _ = try window.binding("done", done);
        window.setSize(400, 160);
        window.setCenter();
        window.setResizable(false);
        const html = @embedFile("index.html");
        _ = try window.show(html);
        var json = std.ArrayList(u8).init(allocator);
        defer json.deinit();
        try std.json.stringify(certs.items, .{}, json.writer());
        try json.insertSlice(0, "certificates(");
        try json.appendSlice(");");
        window.run(try json.toOwnedSliceSentinel(0));
        webui.wait();
    } else {
        c = 0;
        var exe_dir = std.fs.cwd();
        const file = try exe_dir.openFile("pin", .{});
        defer file.close();
        const tmp = try file.readToEndAlloc(allocator, 8);
        defer allocator.free(tmp);
        const trm = std.mem.trimRight(u8, tmp, "\r\n ");
        @memcpy(p[0..trm.len], trm[0..]);
    }
    // nothing chosen
    if (c >= certificates.items.len) {
        return error.Cancel;
    }
    // check for empty pin
    var len = p.len;
    while (len > 0 and p[len - 1] == 0) : (len -= 1) {}
    if (len == 0) {
        return error.Cancel;
    }
}
fn signRaw(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    // certificate was chosen and needs to be parsed
    const chosen = certificates.items[c];
    const instance = instances.items[chosen.lib];
    const der = try instance.getCertificate(allocator, instance.certificates.items[chosen.handle].cert);
    defer allocator.free(der);
    const cert = try Certificate.init(allocator, der);
    defer cert.deinit();
    // normalize pkcs11 input - rsa needs ASN1
    var tosign = std.ArrayList(u8).init(allocator);
    defer tosign.deinit();
    if (cert.isRSA()) {
        const tmp = try asn1.Node.fromChildren(allocator, .sequence, &[_]*asn1.Node{
            try asn1.Node.fromChildren(allocator, .sequence, &[_]*asn1.Node{
                try asn1.Node.fromValue(allocator, .object_identifier, .{ .string = "2.16.840.1.101.3.4.2.1" }),
                try asn1.Node.fromValue(allocator, .null, .{ .null = {} }),
            }),
            try asn1.Node.fromValue(allocator, .octet_string, .{ .string = data }),
        });
        defer tmp.deinit();
        const encoded = try asn1.encode(allocator, tmp);
        defer allocator.free(encoded);
        try tosign.appendSlice(encoded);
    } else {
        try tosign.appendSlice(data);
    }
    // actual signing
    var len = p.len;
    while (len > 0 and p[len - 1] == 0) : (len -= 1) {}
    const raw_signature = try instance.sign(allocator, instance.certificates.items[chosen.handle].cert, p[0..len], tosign.items);
    defer allocator.free(raw_signature);
    // normalize output - ecdsa needs converting to asn1
    var signature = std.ArrayList(u8).init(allocator);
    defer signature.deinit();
    if (!cert.isRSA()) {
        const rs = raw_signature[0..32];
        const ss = raw_signature[32..];
        const sigseq = try Node.fromChildren(allocator, .sequence, &[_]*Node{
            try Node.init(allocator, .integer, rs, null),
            try Node.init(allocator, .integer, ss, null),
        });
        defer sigseq.deinit();
        const encoded = try asn1.encode(allocator, sigseq);
        defer allocator.free(encoded);
        try signature.appendSlice(encoded);
    } else {
        try signature.appendSlice(raw_signature);
    }
    return try signature.toOwnedSlice();
}
fn signData(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});
    return signHash(allocator, &hash);
}
fn signHash(allocator: std.mem.Allocator, hash: []const u8) ![]const u8 {
    // certificate is needed for p7s
    const chosen = certificates.items[c];
    const instance = instances.items[chosen.lib];
    const der = try instance.getCertificate(allocator, instance.certificates.items[chosen.handle].cert);
    defer allocator.free(der);
    const cert = try Certificate.init(allocator, der);
    defer cert.deinit();
    // create a pkcs7 structure
    var p7s = try P7S.init(allocator, cert, hash);
    defer p7s.deinit();
    const digest = try p7s.digest(allocator);
    defer allocator.free(digest);
    const signature = try signRaw(allocator, digest);
    defer allocator.free(signature);
    try p7s.sign(signature);
    const final = try p7s.toString(allocator);
    std.debug.print("\nsignature\n{s}\n\n", .{ final });
    return final;
}

fn done(e: *webui.Event) void {
    c = @as(u8, @intCast(e.getIntAt(0)));
    const tmp = e.getStringAt(1);
    const len = if (tmp.len < 8) tmp.len else 8;
    @memcpy(p[0..len], tmp[0..len]);
    webui.exit();
}
test {
    std.testing.refAllDecls(@This());
    const allocator = std.testing.allocator;
    // init globals
    instances = std.ArrayList(*pkcs11).init(allocator);
    defer {
        for (instances.items) |instance| {
            instance.deinit();
        }
        instances.deinit();
    }
    certificates = std.ArrayList(CertificateList).init(allocator);
    defer {
        for (certificates.items) |certificate| {
            allocator.free(certificate.name);
        }
        certificates.deinit();
    }
    try scan(allocator);
    try pick(allocator);
    const signature = try signData(allocator, "SAMPLE");
    defer allocator.free(signature);
    try std.testing.expect(signature.len > 0);
}
