const std = @import("std");
const builtin = @import("builtin");
const asn1 = @import("asn1/asn1.zig");
const Node = asn1.Node;
const Certificate = @import("asn1/structures/Certificate.zig").Certificate;
const DateTime = @import("helpers/DateTime.zig").DateTime;
const P7S = @import("asn1/structures/P7S.zig").P7S;
const webui = @import("webui");
const CertificateList = struct { lib: u8, handle: u8, name: []const u8 };
const xml = @import("xml");
const httpz = @import("httpz");
const pkcs11 = if (builtin.target.os.tag == .windows)
    @import("lib/pkcs11_win.zig").Lib
else
    @import("lib/pkcs11.zig").Lib
;

// global state - pin and chosen certificate that get populated by webui
var p: [8]u8 = [_]u8{0} ** 8;
var c: u8 = 0;
// global state - instances and found certificates
var instances: std.ArrayList(*pkcs11) = undefined;
var certificates: std.ArrayList(CertificateList) = undefined;
// global state - session
var session: [8]u8 = [_]u8{0} ** 8; 

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    std.debug.print("Starting ...\n", .{});

    const args = try std.process.argsAlloc(allocator);
    if (args.len > 1 and std.mem.eql(u8, args[1], "--prompt")) {
        // Read certs from stdin
        var reader = std.io.bufferedReader(std.io.getStdIn().reader());
        const r = reader.reader();
        var temp: [2048]u8 = undefined;
        const input = try r.readUntilDelimiterOrEof(&temp, '\n');
        const certs = input orelse "certificates([]);";

        // setup and open window
        var window = webui.newWindow();
        _ = try window.binding("done", struct {
            pub fn done(e: *webui.Event) void {
                c = @as(u8, @intCast(e.getIntAt(0)));
                const ti = e.getStringAt(1);
                const tl = if (ti.len < 8) ti.len else 8;
                @memcpy(p[0..tl], ti[0..tl]);
                webui.exit();
            }
        }.done);
        window.setSize(400, 160);
        window.setCenter();
        window.setResizable(false);
        const html = @embedFile("index.html");
        _ = try window.show(html);
        var buff = try allocator.alloc(u8, certs.len + 1);
        @memcpy(buff[0..certs.len], certs);
        buff[certs.len] = 0;
        window.run(buff[0..certs.len :0]);
        webui.wait();
        
        // print chosen value
        try std.io.getStdOut().writer().print("{d}\n{s}\n", .{ c, p});
        return;
    }

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
    std.debug.print("Starting server ...\n", .{});

    try serve(allocator);
}

fn scan(allocator: std.mem.Allocator) !void {
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
            "/usr/lib/libIDPrimePKCS11.dylib",
            "/usr/lib/libOcsPKCS11Wrapper.dylib",
            "/usr/lib/libcmP11.dylib",
            "/usr/lib/bit4ipkcs11.dylib",
        },
        else => .{}
    };
    // remove and discard all old instances
    for (instances.items) |instance| {
        instance.deinit();
    }
    instances.clearRetainingCapacity();
    var exe_dir = std.fs.cwd();
    const file_open = exe_dir.openFile("lib", .{}) catch null;
    if (file_open) |file| {
        defer file.close();
        const tmp = try file.readToEndAlloc(allocator, 255);
        defer allocator.free(tmp);
        const lib = std.mem.trimRight(u8, tmp, "\r\n ");
        std.debug.print(" * hardcoded lib {s}\n", .{lib});
        if (pkcs11.init(allocator, lib) catch null) |instance| {
            instances.append(instance) catch {};
            instance.findCertificates() catch {};
        } } else {
        // scan all available libs
        for (libs) |lib| {
            std.debug.print(" * iterating lib {s}\n", .{lib});
            if (pkcs11.init(allocator, lib) catch null) |instance| {
                instances.append(instance) catch {};
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
            try certificates.append(.{
                .lib = @truncate(i),
                .handle = @truncate(j),
                .name = cer.name(allocator) catch ""
            });
        }
    }
    std.debug.print(" * scanning done\n", .{});
}
fn pick(allocator: std.mem.Allocator) !void {
    std.debug.print(" * picker\n", .{});
    // if testing - use a hardcoded PIN if provided
    if (builtin.is_test) {
        c = 0;
        var exe_dir = std.fs.cwd();
        const file = try exe_dir.openFile("pin", .{});
        defer file.close();
        const tmp = try file.readToEndAlloc(allocator, 8);
        defer allocator.free(tmp);
        const trm = std.mem.trimRight(u8, tmp, "\r\n ");
        @memcpy(p[0..trm.len], trm[0..]);
        return;
    }

    // build a list of certificates to pick from for the UI
    var ui_list = std.ArrayList(struct { handle: u8, name: []const u8 }).init(allocator);
    defer ui_list.deinit();
    for (0.., certificates.items) |i, certificate| {
        try ui_list.append(.{
            .handle = @truncate(i),
            .name = certificate.name
        });
    }

    // reset selection and pin
    c = 0;
    p = [_]u8{0} ** 8;

    const exe_path = try std.fs.selfExePathAlloc(allocator);
    std.debug.print(" * picker spawning child with {d} certificates\n", .{ui_list.items.len});
    const argv = &[_][]const u8{ exe_path, "--prompt" };

    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    try child.spawn();

    // send certificates
    var json = std.ArrayList(u8).init(allocator);
    try std.json.stringify(ui_list.items, .{}, json.writer());
    try json.insertSlice(0, "certificates(");
    try json.appendSlice(");");
    const stdin_writer = child.stdin.?.writer();
    try stdin_writer.print("{s}\n", .{ json.items });
    json.deinit();

    var o: std.ArrayListUnmanaged(u8) = .empty;
    defer o.deinit(allocator);
    var e: std.ArrayListUnmanaged(u8) = .empty;
    defer e.deinit(allocator);
    try child.collectOutput(allocator, &o, &e, 32);
    // wait for the process to finish
    _ = try child.wait();

    // read chosen cert and pin
    var stream = std.io.fixedBufferStream(o.items);
    var reader = stream.reader();
    var c_buffer: [16]u8 = undefined;
    const c_input = try reader.readUntilDelimiterOrEof(&c_buffer, '\n');
    var p_buffer: [16]u8 = undefined;
    const p_input = try reader.readUntilDelimiterOrEof(&p_buffer, '\n');

    // process chosen
    if (c_input) |ci| {
        c = try std.fmt.parseInt(u8, ci, 10);
        std.debug.print(" * picker done - {d}\n", .{c});
    }
    if (p_input) |pi| {
        const len = if (pi.len < 8) pi.len else 8;
        @memcpy(p[0..len], pi[0..len]);
    }

    // nothing chosen
    if (c >= certificates.items.len) {
        return error.Cancel;
    }
    // check for empty pin
    var len = p.len;
    while (len > 0 and p[len - 1] == 0) : (len -= 1) {}
    std.debug.print(" * picker done - pin len {d}\n", .{len});
    if (len == 0) {
        return error.Cancel;
    }
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
    const utc = DateTime.init(std.time.milliTimestamp());
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
    var info = std.ArrayList(u8).init(allocator);
    defer info.deinit();
    try info.appendSlice("<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">");
    try info.appendSlice("<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>");
    try info.appendSlice("<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#");
    if (cert.isRSA()) {
        try info.appendSlice("rsa");
    } else {
        try info.appendSlice("ecdsa");
    }
    try info.appendSlice("-sha256\"/>");
    try info.appendSlice("<Reference URI=\"\">");
    try info.appendSlice("<Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms>");
    try info.appendSlice("<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>");
    try info.appendSlice("<DigestValue>");
    try info.appendSlice(hash_b64);
    try info.appendSlice("</DigestValue></Reference></SignedInfo>");
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
    var signed = std.ArrayList(u8).init(allocator);
    try signed.appendSlice("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n");
    var pos: u64 = 0;
    for (0.., c14n_data[0..]) |i, ch| {
        try signed.append(ch);
        if (ch == '>') {
            pos = i + 1;
            break;
        }
    }
    try signed.appendSlice("<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n");
    try signed.appendSlice(info.items);
    try signed.appendSlice("<SignatureValue>");
    try signed.appendSlice(signature_b64);
    try signed.appendSlice("</SignatureValue><KeyInfo><X509Data><X509Certificate>\n");
    try signed.appendSlice(cert_b64);
    try signed.appendSlice("</X509Certificate></X509Data></KeyInfo></Signature>");
    try signed.appendSlice(c14n_data[pos..]);
    std.debug.print("\nxml\n{s}\n\n", .{ signed.items });
    return signed.toOwnedSlice();
}
fn c14n(allocator: std.mem.Allocator, input: []const u8) ![]const u8 {
    // setup input
    var input_stream = std.io.fixedBufferStream(input);
    var doc = xml.streamingDocument(allocator, input_stream.reader());
    defer doc.deinit();
    var reader = doc.reader(allocator, .{});
    defer reader.deinit();

    // setup output
    var output_stream = std.ArrayList(u8).init(allocator);
    const output = xml.streamingOutput(output_stream.writer());
    var writer = output.writer(allocator, .{ .indent = "" });
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
    return output_stream.toOwnedSlice();
}

const App = struct {
    allocator: std.mem.Allocator
};
fn serve(allocator: std.mem.Allocator) !void {
    var app = App{
        .allocator = allocator
    };
    var server = try httpz.Server(*App).init(allocator, .{ .port = 8090 }, &app);
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
    session = [_]u8{0} ** 8;
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
    const rng = std.crypto.random;
    for (&session) |*s| {
        const index = rng.uintLessThan(u8, 26);
        s.* = letters[index];
    }
    scan(app.allocator) catch {};
    pick(app.allocator) catch {};
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
    var signatureType = std.ArrayList(u8).init(res.arena);
    try signatureType.appendSlice("signature");
    if (try req.jsonObject()) |json| {
        if (json.get("signatureType")) |t| {
            signatureType.clearRetainingCapacity();
            try signatureType.appendSlice(t.string);
        }

        std.debug.print(" - signature is: {s}\n", .{signatureType.items});
        if (json.get("content")) |cnt| {
            std.debug.print(" - content length: {d}\n", .{cnt.string.len});
            var signature = std.ArrayList(u8).init(res.arena);
            if (json.get("sid")) |sid| {
                if (!std.mem.eql(u8, &session, &[_]u8{0} ** 8) and std.mem.eql(u8, &session, sid.string)) {
                    std.debug.print(" - reusing old session: {s}\n", .{sid.string});
                    // reuse old selection and pin
                }
            } else {
                std.debug.print(" - starting new session ...\n", .{});
                scan(app.allocator) catch {};
                pick(app.allocator) catch {};
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
                    try signature.appendSlice(b64);
                }
            } else {
                std.debug.print(" - signing data ...\n", .{});
                const temp = signData(res.arena, cnt.string) catch null;
                if (temp) |sig| {
                    try signature.appendSlice(sig);
                }
            }
            if (signature.items.len > 0) {
                res.header("Access-Control-Allow-Origin", "*");
                try res.json(.{
                    .version = "1.0",
                    .signatureType = try signatureType.toOwnedSlice(),
                    .signature = try signature.toOwnedSlice(),
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
        .signatureType = try signatureType.toOwnedSlice(),
        .signature = null,
        .status = "failed",
        .reasonCode = 500,
        .reasonText = "Invalid input",
        .errorCode = 1
    }, .{});
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

    const xml_test = try signXML(allocator, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root></root>");
    defer allocator.free(xml_test);
    try std.testing.expect(xml_test.len > 0);

    const signature = try signData(allocator, "SAMPLE");
    defer allocator.free(signature);
    try std.testing.expect(signature.len > 0);
}
