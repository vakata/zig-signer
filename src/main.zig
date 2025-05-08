const std = @import("std");
const os = @import("builtin").target.os;
const pkcs11 = @import("pkcs11.zig");
const Certificate = @import("Certificate.zig").Certificate;
const webui = @import("webui");

var p: [8]u8 = [_]u8{0} ** 8;
var c: u8 = 0;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    _ = signData(allocator, "SAMPLE") catch null;
}

fn signData(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});
    return signHash(allocator, &hash);
}
// scan for pkcs11 providers, list certificates and sign a string
fn signHash(allocator: std.mem.Allocator, hash: []const u8) ![]const u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();
    // libs default locations per OS
    const libs: []const []const u8 = comptime switch (os.tag) {
        .macos => &.{
            "/Library/Frameworks/eToken.framework/Versions/A/libIDPrimePKCS11.dylib"
        },
        else => .{}
    };

    // create all available instances
    var instances = std.ArrayList(*pkcs11.Lib).init(arena_allocator);
    defer {
        for (instances.items) |instance| {
            instance.deinit();
        }
        instances.deinit();
    }
    for (libs) |lib| {
        if (pkcs11.Lib.init(arena_allocator, lib) catch null) |instance| {
            instances.append(instance) catch {};
        }
    }
    
    // collect certificates
    var certificates = std.ArrayList(*Certificate).init(arena_allocator);
    defer {
        for (certificates.items) |certificate| {
            certificate.deinit();
        }
        certificates.deinit();
    }
    for (instances.items) |instance| {
        instance.getCertificates(arena_allocator, &certificates);
    }
    var certs = std.ArrayList(struct { handle: u64, name: []const u8 }).init(arena_allocator);
    defer certs.deinit();
    for (0.., certificates.items) |i, certificate| {
        try certs.append(.{
            .handle = i,
            .name = try certificate.name(arena_allocator)
        });
    }

    c = 0;
    p = [_]u8{0} ** 8;

    var window = webui.newWindow();
    _ = try window.binding("pin", pin);
    _ = try window.binding("ready", ready);
    window.setSize(400, 120);
    window.setCenter();
    window.setResizable(false);
    const html = @embedFile("index.html");
    _ = try window.show(html);
    var json = std.ArrayList(u8).init(allocator);
    defer json.deinit();
    try std.json.stringify(certs.items, .{}, json.writer());
    try json.insertSlice(0, "r(");
    try json.appendSlice(");");
    window.run(try json.toOwnedSliceSentinel(0));
    webui.wait();

    // certificate is chosen and parsed
    const certificate = certificates.items[c];

    // proceed to signing
    var len = p.len;
    while (len > 0 and p[len - 1] == 0) : (len -= 1) {}
    const signature = try certificate.signDetached(allocator, hash, p[0..len]);
    std.debug.print("\nsignature\n{s}\n\n", .{ signature });

    c = 0;
    p = [_]u8{0} ** 8;

    return signature;
}
fn ready(e: *webui.Event) void {
    std.debug.print("asdf\n\n", .{});
    e.getWindow().run("p();");
}
fn pin(e: *webui.Event) void {
    std.debug.print("asdf\n\n", .{});
    c = @as(u8, @intCast(e.getIntAt(0)));
    const tmp = e.getStringAt(1);
    const len = if (tmp.len < 8) tmp.len else 8;
    @memcpy(p[0..len], tmp[0..len]);
    std.debug.print("{d} {any}\n\n", .{c, p});
    webui.exit();
}
test "sign" {
    const allocator = std.testing.allocator;
    const signature = try signData(allocator, "SAMPLE");
    defer allocator.free(signature);
    try std.testing.expect(signature.len > 0);
}
