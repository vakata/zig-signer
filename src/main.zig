const std = @import("std");
const builtin = @import("builtin");
const asn1 = @import("asn1/asn1.zig");
const Certificate = @import("asn1/structures/Certificate.zig").Certificate;
const DateTime = @import("helpers/Datetime.zig").DateTime;
const P7S = @import("asn1/structures/P7S.zig").P7S;
const xml = @import("xml");
const httpz = @import("httpz");
const pkcs11 = @import("lib/pkcs11.zig").Lib;
const Node = asn1.Node;
const CertificateList = struct { lib: u8, handle: u8, name: []const u8 };
const PickerSelection = struct { certificate: u8, pin: [8]u8 };

// global state - pin and chosen certificate
var p: [8]u8 = @splat(0);
var c: u8 = 0;
// global state - instances and found certificates
var instances: std.ArrayList(*pkcs11) = undefined;
var certificates: std.ArrayList(CertificateList) = undefined;
// global state - session
var session: [8]u8 = @splat(0);
var gpa: std.mem.Allocator = undefined;
var gio: std.Io = undefined;
var gargs: std.process.Args = undefined;

pub fn main(init: std.process.Init) !void {
    gpa = init.gpa;
    gio = init.io;
    gargs = init.minimal.args;
    const allocator = init.gpa;
    std.debug.print("Starting ...\n", .{});

    // init globals
    instances = .empty;
    defer {
        for (instances.items) |instance| {
            instance.deinit();
        }
        instances.deinit(allocator);
    }
    certificates = .empty;
    defer {
        for (certificates.items) |certificate| {
            allocator.free(certificate.name);
        }
        certificates.deinit(gpa);
    }
    std.debug.print("Starting server ...\n", .{});

    try serve(init.io, allocator);
}

fn scan(allocator: std.mem.Allocator, io: std.Io) !void {
    std.debug.print(" * scanning ...\n", .{});
    // libs default locations per OS
    const libs: []const []const u8 = comptime switch (builtin.target.os.tag) {
        .macos => &.{
            "/Library/Frameworks/eToken.framework/Versions/A/libIDPrimePKCS11.dylib",
            "/Library/AWP/lib/libOcsPKCS11Wrapper.dylib",
            "/Applications/Charismathics/libcmP11.dylib",
            "/Library/Bit4id/PKI Manager/bit4ipkcs11.dylib",
        },
        .windows => &.{
            "cvP11.dll",
            "cmP11.dll",
            "cmP1164.dll",
            "idprimepkcs11.dll",
            "OcsPKCS11Wrapper.dll",
            "eTPKCS11.dll",
            "bit4ipki.dll",
        },
        .linux => &.{
            // Arch Linux and other distributions using /usr/lib.
            "/usr/lib/libIDPrimePKCS11.so",
            "/usr/lib/libOcsPKCS11Wrapper.so",
            "/usr/lib/libcmP11.so",
            "/usr/lib/libeTPkcs11.so",
            "/usr/lib/libbit4ipki.so",
            "/usr/lib/opensc-pkcs11.so",
            "/usr/lib/pkcs11/opensc-pkcs11.so",

            // Debian/Ubuntu x86_64 multiarch locations.
            "/usr/lib/x86_64-linux-gnu/libIDPrimePKCS11.so",
            "/usr/lib/x86_64-linux-gnu/libOcsPKCS11Wrapper.so",
            "/usr/lib/x86_64-linux-gnu/libcmP11.so",
            "/usr/lib/x86_64-linux-gnu/libeTPkcs11.so",
            "/usr/lib/x86_64-linux-gnu/libbit4ipki.so",
            "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
            "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so",

            // Debian/Ubuntu aarch64 multiarch locations.
            "/usr/lib/aarch64-linux-gnu/libIDPrimePKCS11.so",
            "/usr/lib/aarch64-linux-gnu/libOcsPKCS11Wrapper.so",
            "/usr/lib/aarch64-linux-gnu/libcmP11.so",
            "/usr/lib/aarch64-linux-gnu/libeTPkcs11.so",
            "/usr/lib/aarch64-linux-gnu/libbit4ipki.so",
            "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so",
            "/usr/lib/aarch64-linux-gnu/pkcs11/opensc-pkcs11.so",

            // Common vendor-specific subdirectories.
            "/usr/lib/bit4id/libbit4ipki.so",
            "/usr/local/lib/libIDPrimePKCS11.so",
            "/usr/local/lib/libOcsPKCS11Wrapper.so",
            "/usr/local/lib/libcmP11.so",
            "/usr/local/lib/libeTPkcs11.so",
            "/usr/local/lib/libbit4ipki.so",
            "/usr/local/lib/opensc-pkcs11.so",
        },
        else => .{}
    };
    // remove and discard all old instances
    for (instances.items) |instance| {
        instance.deinit();
    }
    instances.clearRetainingCapacity();
    const tmp = std.Io.Dir.cwd().readFileAlloc(
        io,
        "lib",
        allocator,
        .limited(255),
    ) catch null;
    if (tmp) |data| {
        defer allocator.free(data);
        const lib = std.mem.trimEnd(u8, data, "\r\n ");
        std.debug.print(" * hardcoded lib {s}\n", .{lib});
        if (pkcs11.init(allocator, lib) catch null) |instance| {
            instances.append(gpa, instance) catch {};
            instance.findCertificates() catch {};
        } } else {
        // scan all available libs
        for (libs) |lib| {
            std.debug.print(" * iterating lib {s}\n", .{lib});
            if (pkcs11.init(allocator, lib) catch null) |instance| {
                instances.append(gpa, instance) catch {};
                instance.findCertificates() catch {};
            }
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
            std.debug.print(" * found lib/cert {d}/{d}\n", .{i,j});
            const der = instance.getCertificate(allocator, certificate.cert) catch { continue; };
            defer allocator.free(der);
            const cer = Certificate.init(allocator, der) catch { continue; };
            defer cer.deinit();
            try certificates.append(gpa, .{
                .lib = @truncate(i),
                .handle = @truncate(j),
                .name = cer.name(allocator) catch ""
            });
        }
    }
    std.debug.print(" * scanning done\n", .{});
}
fn pick(allocator: std.mem.Allocator, io: std.Io) !void {
    std.debug.print(" * picker\n", .{});

    // reset selection and pin
    c = 0;
    p = @splat(0);

    if (certificates.items.len == 0)
        return error.Cancel;

    const picker_name = if (builtin.target.os.tag == .windows) "signer-picker.exe" else "signer-picker";
    var process_args = try std.process.Args.Iterator.initAllocator(gargs, allocator);
    defer process_args.deinit();
    const signer_path = process_args.next() orelse return error.InvalidExecutablePath;
    const picker_path = if (std.fs.path.dirname(signer_path)) |executable_dir|
        try std.fs.path.join(allocator, &.{ executable_dir, picker_name })
    else
        try allocator.dupe(u8, picker_name);
    defer allocator.free(picker_path);

    var picker_args: std.ArrayList([]const u8) = .empty;
    defer picker_args.deinit(allocator);
    try picker_args.append(allocator, picker_path);
    for (certificates.items) |certificate|
        try picker_args.append(allocator, certificate.name);

    const picker_result = try std.process.run(allocator, io, .{
        .argv = picker_args.items,
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
        .create_no_window = false,
    });
    defer {
        @memset(picker_result.stdout, 0);
        @memset(picker_result.stderr, 0);
        allocator.free(picker_result.stdout);
        allocator.free(picker_result.stderr);
    }

    switch (picker_result.term) {
        .exited => |code| if (code != 0) return error.Cancel,
        else => return error.Cancel,
    }

    const selection = try parsePickerResult(picker_result.stdout, certificates.items.len);
    c = selection.certificate;
    p = selection.pin;

    // check for empty pin
    var len = p.len;
    while (len > 0 and p[len - 1] == 0) : (len -= 1) {}
    std.debug.print(" * picker done - pin len {d}\n", .{len});
    if (len == 0) {
        return error.Cancel;
    }
}

fn parsePickerResult(output: []const u8, certificate_count: usize) !PickerSelection {
    const marker = "ZIG_SIGNER_RESULT ";
    const marker_pos = std.mem.lastIndexOf(u8, output, marker) orelse return error.InvalidPickerOutput;
    var fields = std.mem.tokenizeAny(u8, output[marker_pos + marker.len..], " \r\n\t");
    const selected_text = fields.next() orelse return error.InvalidPickerOutput;
    const pin_hex = fields.next() orelse return error.InvalidPickerOutput;
    var pin = @as([8]u8, @splat(0));
    if (pin_hex.len == 0 or pin_hex.len > pin.len * 2 or pin_hex.len % 2 != 0)
        return error.InvalidPickerOutput;

    const selected = try std.fmt.parseInt(usize, selected_text, 10);
    if (selected >= certificate_count or selected > std.math.maxInt(u8))
        return error.InvalidPickerOutput;
    _ = try std.fmt.hexToBytes(&pin, pin_hex);
    return .{ .certificate = @intCast(selected), .pin = pin };
}

test "parse NAppGUI picker result" {
    const selection = try parsePickerResult("NAppGUI log\nZIG_SIGNER_RESULT 2 31323334\n", 3);
    try std.testing.expectEqual(@as(u8, 2), selection.certificate);
    try std.testing.expectEqualSlices(u8, "1234\x00\x00\x00\x00", &selection.pin);
}

test "reject invalid NAppGUI picker result" {
    try std.testing.expectError(error.InvalidPickerOutput, parsePickerResult("", 1));
    try std.testing.expectError(error.InvalidPickerOutput, parsePickerResult("ZIG_SIGNER_RESULT 1 3132\n", 1));
    try std.testing.expectError(error.InvalidPickerOutput, parsePickerResult("ZIG_SIGNER_RESULT 0 123\n", 1));
}
fn signRaw(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    std.debug.print(" ! signing raw\n", .{});
    if (c >= certificates.items.len) {
        return error.NoCertificate;
    }
    // certificate was chosen and needs to be parsed
    const chosen = certificates.items[c];
    const instance = instances.items[chosen.lib];
    const der = try instance.getCertificate(allocator, instance.certificates.items[chosen.handle].cert);
    defer allocator.free(der);
    const cert = try Certificate.init(allocator, der);
    defer cert.deinit();
    // normalize pkcs11 input - rsa needs ASN1
    var tosign: std.ArrayList(u8) = .empty;
    defer tosign.deinit(allocator);
    if (cert.isRSA()) {
        std.debug.print("cert is rsa", .{});
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
        try tosign.appendSlice(allocator, encoded);
    } else {
        try tosign.appendSlice(allocator, data);
    }
    // actual signing
    var len = p.len;
    while (len > 0 and p[len - 1] == 0) : (len -= 1) {}
    const raw_signature = try instance.sign(allocator, instance.certificates.items[chosen.handle].cert, p[0..len], tosign.items);
    defer allocator.free(raw_signature);
    // normalize output - ecdsa needs converting to asn1
    var signature: std.ArrayList(u8) = .empty;
    defer signature.deinit(allocator);
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
        try signature.appendSlice(allocator, encoded);
    } else {
        try signature.appendSlice(allocator, raw_signature);
    }
    return try signature.toOwnedSlice(allocator);
}
fn signData(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    std.debug.print(" ! signing data\n", .{});
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});
    return signHash(allocator, &hash);
}
fn signHash(allocator: std.mem.Allocator, hash: []const u8) ![]const u8 {
    std.debug.print(" ! signing hash\n", .{});
    if (c >= certificates.items.len) {
        return error.NoCertificate;
    }
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
    // calculate the current timestamp
    const utc = DateTime.init(std.Io.Clock.real.now(gio).toMilliseconds());
    const datetime = try allocator.alloc(u8, 13);
    defer allocator.free(datetime);
    _ = try std.fmt.bufPrint(
        datetime,
        "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z",
        .{ utc.year % 100, utc.month, utc.day, utc.hour, utc.minute, utc.second }
    );
    // add the timestamp to the p7s
    try p7s.timestamp(datetime);
    // calculate the digest
    const digest = try p7s.digest(allocator);
    defer allocator.free(digest);
    // sign the digest
    const signature = try signRaw(allocator, digest);
    defer allocator.free(signature);
    // apply the signature to the p7s
    try p7s.sign(signature);
    // get the base64 encoded result
    const final = try p7s.toString(allocator);
    std.debug.print("\nsignature\n{s}\n\n", .{ final });
    return final;
}
fn signXML(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    std.debug.print(" ! signing xml\n", .{});
    if (c >= certificates.items.len) {
        return error.NoCertificate;
    }
    // canonicalize
    const c14n_data = try c14n(allocator, data);
    defer allocator.free(c14n_data);
    // hash the data
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(c14n_data, &hash, .{});
    // base64 encode the hash
    const hash_b64 = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(hash.len));
    defer allocator.free(hash_b64);
    _ = std.base64.standard.Encoder.encode(hash_b64, &hash);
    // get the certificate as it is needed in the xmldsig
    const chosen = certificates.items[c];
    const instance = instances.items[chosen.lib];
    const der = try instance.getCertificate(allocator, instance.certificates.items[chosen.handle].cert);
    defer allocator.free(der);
    const cert = try Certificate.init(allocator, der);
    defer cert.deinit();
    // base64 encode the certificate
    const cert_b64 = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(der.len));
    defer allocator.free(cert_b64);
    _ = std.base64.standard.Encoder.encode(cert_b64, der);
    // build signed info
    var info: std.ArrayList(u8) = .empty;
    defer info.deinit(allocator);
    try info.appendSlice(allocator, "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">");
    try info.appendSlice(allocator, "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>");
    try info.appendSlice(allocator, "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#");
    if (cert.isRSA()) {
        try info.appendSlice(allocator, "rsa");
    } else {
        try info.appendSlice(allocator, "ecdsa");
    }
    try info.appendSlice(allocator, "-sha256\"/>");
    try info.appendSlice(allocator, "<Reference URI=\"\">");
    try info.appendSlice(allocator, "<Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms>");
    try info.appendSlice(allocator, "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>");
    try info.appendSlice(allocator, "<DigestValue>");
    try info.appendSlice(allocator, hash_b64);
    try info.appendSlice(allocator, "</DigestValue></Reference></SignedInfo>");
    // canonicalize
    const c14n_info = try c14n(allocator, info.items);
    defer allocator.free(c14n_info);
    // build the signerinfo hash
    var info_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(c14n_info, &info_hash, .{});
    // sign the hash
    const signature = try signRaw(allocator, &info_hash);
    defer allocator.free(signature);
    // base64 encode the signature
    const signature_b64 = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(signature.len));
    defer allocator.free(signature_b64);
    _ = std.base64.standard.Encoder.encode(signature_b64, signature);
    // build the xml
    var signed: std.ArrayList(u8) = .empty;
    try signed.appendSlice(allocator, "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n");
    var pos: u64 = 0;
    for (0.., c14n_data[0..]) |i, ch| {
        try signed.append(allocator, ch);
        if (ch == '>') {
            pos = i + 1;
            break;
        }
    }
    try signed.appendSlice(allocator, "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n");
    try signed.appendSlice(allocator, info.items);
    try signed.appendSlice(allocator, "<SignatureValue>");
    try signed.appendSlice(allocator, signature_b64);
    try signed.appendSlice(allocator, "</SignatureValue><KeyInfo><X509Data><X509Certificate>\n");
    try signed.appendSlice(allocator, cert_b64);
    try signed.appendSlice(allocator, "</X509Certificate></X509Data></KeyInfo></Signature>");
    try signed.appendSlice(allocator, c14n_data[pos..]);
    std.debug.print("\nxml\n{s}\n\n", .{ signed.items });
    return signed.toOwnedSlice(allocator);
}
fn c14n(allocator: std.mem.Allocator, input: []const u8) ![]const u8 {
    // setup input
    var input_reader: std.Io.Reader = .fixed(input);
    var doc: xml.Reader.Streaming = .init(allocator, &input_reader, .{});
    defer doc.deinit();
    var reader = &doc.interface;

    // setup output
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var writer: xml.Writer = .init(allocator, &output.writer, .{ .indent = "" });
    defer writer.deinit();

    // parse and canonicalize
    while (true) {
        const node = reader.read() catch |err| {
            switch (err) {
            error.MalformedXml => {
                return error.MalformedXml;
            },
            else => |other| return other,
        }};
        switch (node) {
            .eof => break,
            .xml_declaration, .comment => {}, // ignored in canonical form
            .element_start => {
                try writer.elementStart(reader.elementName());

                const sorted_attrs = try allocator.alloc(usize, reader.attributeCount());
                defer allocator.free(sorted_attrs);
                for (0..reader.attributeCount()) |i| sorted_attrs[i] = i;
                std.sort.pdq(usize, sorted_attrs, reader, struct {
                    fn lessThan(r: @TypeOf(reader), lhs: usize, rhs: usize) bool {
                        if (std.mem.eql(u8, r.attributeNameNs(lhs).prefix, "xmlns") and !std.mem.eql(u8, r.attributeNameNs(rhs).prefix, "xmlns")) {
                            return true; }
                        if (!std.mem.eql(u8, r.attributeNameNs(lhs).prefix, "xmlns") and std.mem.eql(u8, r.attributeNameNs(rhs).prefix, "xmlns")) {
                            return false;
                        }
                        return std.mem.lessThan(u8, r.attributeName(lhs), r.attributeName(rhs));
                    }
                }.lessThan);
                for (sorted_attrs) |i| {
                    try writer.attribute(reader.attributeName(i), try reader.attributeValue(i));
                }
            },
            .element_end => {
                try writer.elementEnd();
            },
            .pi => {
                try writer.pi(reader.piTarget(), try reader.piData());
            },
            .text => {
                try writer.text(try reader.text());
            },
            .cdata => {
                try writer.text(try reader.cdata());
            },
            .character_reference => {
                var buf: [4]u8 = undefined;
                const len = std.unicode.utf8Encode(reader.characterReferenceChar(), &buf) catch unreachable;
                try writer.text(buf[0..len]);
            },
            .entity_reference => {
                const value = xml.predefined_entities.get(reader.entityReferenceName()) orelse unreachable;
                try writer.text(value);
            },
        }
    }
    return output.written();
}

const App = struct {
    allocator: std.mem.Allocator,
    io: std.Io
};
fn serve(io: std.Io, allocator: std.mem.Allocator) !void {
    var app = App{
        .allocator = allocator,
        .io = io
    };
    var server = try httpz.Server(*App).init(io, allocator, .{ .address = .localhost(8090) }, &app);
    defer server.deinit();
    defer server.stop();

    var router = try server.router(.{});
    router.get("/version", httpVersion, .{});
    router.post("/sign", httpSign, .{});
    router.post("/signer/sign", httpSign, .{});
    router.get("/signer/selectSigner", httpSelect, .{});
    router.post("/signer/selectSigner", httpSelect, .{});
    router.get("/signer/clearSigner", httpClear, .{});
    router.post("/signer/clearSigner", httpClear, .{});

    std.debug.print("Server listening ...\n", .{});
    try server.listen();
}
fn httpVersion(_: *App, _: *httpz.Request, res: *httpz.Response) !void {
    std.debug.print("/version\n", .{});
    res.header("Access-Control-Allow-Origin", "*");
    res.body = 
        \\{
        \\    "version":"1.0",
        \\    "httpMethods":"POST",
        \\    "contentTypes":"data",
        \\    "signatureTypes":"signature, xmldsig, raw",
        \\    "selectorAvailable":false,
        \\    "hashAlgorithms":"SHA256",
        \\    "services":[
        \\        {
        \\            "root":"signer",
        \\            "name":"ZIG Signer Service",
        \\            "desc":"Provides signing services for data",
        \\            "version":"0.1",
        \\            "vendor":"vakata",
        \\            "methods":[ "sign", "selectSigner" ]
        \\        }
        \\    ]
        \\}
    ;
}
fn httpClear(_: *App, _: *httpz.Request, res: *httpz.Response) !void { std.debug.print("/clear\n", .{});
    session = @splat(0);
    res.header("Access-Control-Allow-Origin", "*");
    try res.json(.{
        .version = "1.0",
        .status = "ok",
        .reasonCode = 200,
        .reasonText = "Cleared OK",
        .errorCode = 0
    }, .{});
}
fn httpSelect(app: *App, _: *httpz.Request, res: *httpz.Response) !void {
    std.debug.print("/select\n", .{});
    const letters = "abcdefghijklmnopqrstuvwxyz";
    const rng_impl: std.Random.IoSource = .{ .io = app.io };
    const rng = rng_impl.interface();
    for (&session) |*s| {
        const index = rng.uintLessThan(u8, letters.len);
        s.* = letters[index];
    }
    scan(app.allocator, app.io) catch {};
    try pick(app.allocator, app.io);
    const signature = try signData(res.arena, "SESSION");
    res.header("Access-Control-Allow-Origin", "*");
    try res.json(.{
        .version = "1.0",
        .signatureType = "signature",
        .signature = signature,
        .sid = session,
        .status = "ok",
        .reasonCode = 200,
        .reasonText = "Signed OK",
        .errorCode = 0
    }, .{});
    return;
}
fn httpSign(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    std.debug.print("/sign\n", .{});
    var signatureType: std.ArrayList(u8) = .empty;
    try signatureType.appendSlice(res.arena, "signature");
    if (try req.jsonObject()) |json| {
        if (json.get("signatureType")) |t| {
            signatureType.clearRetainingCapacity();
            try signatureType.appendSlice(res.arena, t.string);
        }

        std.debug.print(" - signature is: {s}\n", .{signatureType.items});
        if (json.get("content")) |cnt| {
            std.debug.print(" - content length: {d}\n", .{cnt.string.len});
            var signature: std.ArrayList(u8) = .empty;
            if (json.get("sid")) |sid| {
                if (!std.mem.allEqual(u8, &session, 0) and std.mem.eql(u8, &session, sid.string)) {
                    std.debug.print(" - reusing old session: {s}\n", .{sid.string});
                    // reuse old selection and pin
                }
            } else {
                std.debug.print(" - starting new session ...\n", .{});
                scan(app.allocator, app.io) catch {};
                try pick(app.allocator, app.io);
            }
            if (std.mem.eql(u8, "xmldsig", signatureType.items)) {
                // decode the input
                const decoded = try res.arena.alloc(u8, try std.base64.standard.Decoder.calcSizeForSlice(cnt.string));
                _ = try std.base64.standard.Decoder.decode(decoded, cnt.string);
                // sign
                std.debug.print(" - signing xml ...\n", .{});
                const temp = signXML(res.arena, decoded) catch null;
                // encode the output
                if (temp) |sig| {
                    const b64 = try res.arena.alloc(u8, std.base64.standard.Encoder.calcSize(sig.len));
                    _ = std.base64.standard.Encoder.encode(b64, sig);
                    try signature.appendSlice(res.arena, b64);
                }
            } else if (std.mem.eql(u8, "raw", signatureType.items)) {
                std.debug.print(" - signing raw ...\n", .{});
                const temp = signRaw(res.arena, cnt.string) catch null;
                if (temp) |sig| {
                    const b64 = try res.arena.alloc(u8, std.base64.standard.Encoder.calcSize(sig.len));
                    _ = std.base64.standard.Encoder.encode(b64, sig);
                    try signature.appendSlice(res.arena, b64);
                }
            } else if (std.mem.eql(u8, "hash", signatureType.items)) {
                std.debug.print(" - signing hash ...\n", .{});
                const temp = signHash(res.arena, cnt.string) catch null;
                if (temp) |sig| {
                    try signature.appendSlice(res.arena, sig);
                }
            } else {
                const decoded = try res.arena.alloc(u8, try std.base64.standard.Decoder.calcSizeForSlice(cnt.string));
                _ = try std.base64.standard.Decoder.decode(decoded, cnt.string);
                std.debug.print(" - signing data ...\n", .{});
                const temp = signData(res.arena, decoded) catch null;
                if (temp) |sig| {
                    try signature.appendSlice(res.arena, sig);
                }
            }
            if (signature.items.len > 0) {
                res.header("Access-Control-Allow-Origin", "*");
                try res.json(.{
                    .version = "1.0",
                    .signatureType = try signatureType.toOwnedSlice(res.arena),
                    .signature = try signature.toOwnedSlice(res.arena),
                    .status = "ok",
                    .reasonCode = 200,
                    .reasonText = "Signed OK",
                    .errorCode = 0
                }, .{});
                return;
            }
        }
    }
    res.header("Access-Control-Allow-Origin", "*");
    try res.json(.{
        .version = "1.0",
        .signatureType = try signatureType.toOwnedSlice(res.arena),
        .signature = null,
        .status = "failed",
        .reasonCode = 500,
        .reasonText = "Invalid input",
        .errorCode = 1
    }, .{});
}
