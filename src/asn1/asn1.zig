const std = @import("std");

// Long tags are only partially supported - they will not break the parsing
pub const Tag = enum(u8) {
    // helper enums defning the tag
    const Type = enum (u8) {
        constructed = 0b00100000,
        primitive   = 0b00000000,
    };
    const Class = enum (u8) {
        universal   = 0b00000000,
        application = 0b01000000,
        context     = 0b10000000,
        private     = 0b11000000,
    };

    _none = 0, // special value for this parser
    boolean = 1,
    integer,
    bit_string,
    octet_string,
    null,
    object_identifier,
    object_descriptor,
    _external_type, // should only appear as constructed
    real_type,
    enumerated_type,
    _embedded_pdv,
    utf8_string,
    relative_oid,
    time,
    _reserved,
    _sequence, // should only appear as constructed
    _set, // should only appear as constructed
    numeric_string,
    printable_string,
    teletex_string,
    videotex_string,
    ia5_string,
    utc_time,
    generalized_time,
    graphic_string,
    visible_string,
    general_string,
    universal_string,
    unrestricted_string,
    bmp_string,
    bit_string_constructed = 3 | @intFromEnum(Type.constructed),
    octet_string_constructed = 4 | @intFromEnum(Type.constructed),
    sequence = 16 | @intFromEnum(Type.constructed),
    set = 17 | @intFromEnum(Type.constructed),
    _implicit0 = 128,
    _implicit1,
    _implicit2,
    _implicit3,
    _implicit4,
    _implicit5,
    _implicit6,
    _implicit7,
    _implicit8,
    _implicit9,
    _explicit0 = 160,
    _explicit1,
    _explicit2,
    _explicit3,
    _explicit4,
    _explicit5,
    _explicit6,
    _explicit7,
    _explicit8,
    _explicit9,
    _, // all else (like long tags)

    pub fn isPrimitive(self: Tag) bool {
        return !self.isConstructed();
    }
    pub fn isConstructed(self: Tag) bool {
        return @intFromEnum(self) & @intFromEnum(Type.constructed) != 0;
    }
    pub fn isLong(self: Tag) bool {
        return @intFromEnum(self) & 0b00011111 == 31;
    }
    pub fn val(self: *const Tag) u8 {
        return @intFromEnum(self) & 0b00011111;
    }
    pub fn class(self: *const Tag) Class {
        const tmp = @intFromEnum(self);
            if (tmp & @intFromEnum(Class.application) == @intFromEnum(Class.application)) {
            return Class.application;
        }
        if (tmp & @intFromEnum(Class.private) == @intFromEnum(Class.private)) {
            return Class.private;
        }
        if (tmp & @intFromEnum(Class.context) == @intFromEnum(Class.context)) {
            return Class.context;
        }
        return Class.universal;
    }
    pub fn isUniversal(self: *const Tag) bool {
        return self.class() == Class.universal;
    }
    pub fn isApplication(self: *const Tag) bool {
        return self.class() == Class.application;
    }
    pub fn isPrivate(self: *const Tag) bool {
        return self.class() == Class.private;
    }
    pub fn isContext(self: *const Tag) bool {
        return self.class() == Class.context;
    }
};

pub const Val = union(enum) {
    int: u64,
    bool: bool,
    float: f64,
    string: []const u8,
    null,
};

pub const Node = struct {
    allocator: std.mem.Allocator,
    nodes: std.ArrayList(*Node),
    val: []const u8, // always encoded
    tag: Tag,
    imp: Tag,
    own: bool,

    // init is used mainly when decoding - the val property is not owned and will not be freed
    pub fn init(
        allocator: std.mem.Allocator,
        tag: Tag,
        val: []const u8,
        nodes: ?std.ArrayList(*Node)
    ) !*Node {
        const self = try allocator.create(Node);
        self.* = .{
            .allocator = allocator,
            .tag = tag,
            .val = val,
            .nodes = nodes orelse std.ArrayList(*Node).init(allocator),
            .imp = ._none,
            .own = false
        };
        return self;
    }
    // used when encoding
    pub fn fromChildren(
        allocator: std.mem.Allocator,
        tag: Tag,
        nodes: []const *Node
    ) !*Node {
        var node_list = std.ArrayList(*Node).init(allocator);
        try node_list.appendSlice(nodes);
        return try Node.init(allocator, tag, "", node_list);
    }
    // used when encoding - the .val property is duplicated as needed and will be freed
    pub fn fromValue(
        allocator: std.mem.Allocator,
        tag: Tag,
        val: Val,
    ) !*Node {
        var node = try Node.init(allocator, tag, try encodeValue(allocator, tag, val), null);
        node.own = true;
        return node;
    }
    pub fn implicitFromChildren(
        allocator: std.mem.Allocator,
        tag: Tag,
        imp: Tag,
        nodes: []const *Node
    ) !*Node {
        const new_tag = @intFromEnum(tag) | @intFromEnum(Tag.Type.constructed);
        var node_list = std.ArrayList(*Node).init(allocator);
        try node_list.appendSlice(nodes);
        var node = try Node.init(allocator, @enumFromInt(new_tag), "", node_list);
        node.imp = imp;
        return node;
    }
    pub fn implicitFromValue(
        allocator: std.mem.Allocator,
        tag: Tag,
        imp: Tag,
        val: Val,
    ) !*Node {
        var new_tag = @intFromEnum(tag);
        if (imp.isConstructed()) {
            new_tag |= @intFromEnum(Tag.Type.constructed);
        }
        var node = try Node.init(allocator, @enumFromInt(new_tag), try encodeValue(allocator, imp, val), null);
        node.own = true;
        node.imp = imp;
        return node;
    }
    pub fn deinit(self: *Node) void {
        if (self.own) {
            self.allocator.free(self.val);
        }
        for (self.nodes.items) |node| {
            node.deinit();
        }
        self.nodes.deinit();
        self.allocator.destroy(self);
    }
    pub fn value(self: *Node) !Val {
        return try decodeValue(self.allocator, self.tag, self.val);
    }
    pub fn children(self: *Node) []*Node {
        return self.nodes.items;
    }
    pub fn child(self: *Node, idx: u64) *Node {
        return self.children()[idx];
    }
};

pub fn decode(allocator: std.mem.Allocator, buf: []const u8) !std.ArrayList(*Node) {
    var stream = std.io.fixedBufferStream(buf);
    var reader = stream.reader();
    var nodes = std.ArrayList(*Node).init(allocator);
    while (stream.pos < stream.buffer.len) {
        var tmp: u8 = undefined;

        // parse tag
        const tag = reader.readByte() catch { break; };
        if ((tag & 31) == 31) { // long tags are not supported but at least parse them
            while (true) {
                tmp = reader.readByte() catch { break; };
                if (tmp & 128 == 0) {
                    break;
                }
            }
        }

        var beg: u64 = 0;
        var end: u64 = 0;
        var len: u64 = 0;

        // parse length
        tmp = reader.readByte() catch { break; };
        if (tmp == 128) {
            beg = stream.pos;
            while (true) {
                tmp = reader.readByte() catch { break; };
                if (tmp == 0) {
                    tmp = reader.readByte() catch { break; };
                    if (tmp == 0) {
                        break;
                    }
                }
            }
            end = stream.pos - 2;
            len = stream.pos - beg;
            stream.pos = beg;
        } else if (tmp & 128 == 128) {
            for (0..(tmp & 127)) |_| {
                tmp = reader.readByte() catch { break; };
                len <<= 8;
                len |= tmp;
            }
            beg = stream.pos;
            end = beg + len;
        } else {
            len = tmp;
            beg = stream.pos;
            end = beg + len;
        }

        // create node
        const node = try Node.init(allocator, @enumFromInt(tag), buf[beg..end], null);
        if (node.tag.isConstructed()) {
            node.nodes = try decode(allocator, buf[beg..end]);
        }
        try nodes.append(node);
        stream.pos = beg + len;
    }
    return nodes;
}

pub fn encode(allocator: std.mem.Allocator, node: *Node) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    var len: u64 = 0;
    if (node.tag.isConstructed() and node.nodes.items.len > 0) {
        var children = std.ArrayList([]const u8).init(allocator);
        defer {
            for (children.items) |c| {
                allocator.free(c);
            }
            children.deinit();
        }
        for (node.nodes.items) |n| {
            const val = try encode(allocator, n);
            try children.append(val);
        }
        if (node.tag == .set or node.imp == .set) {
            std.mem.sort(
                []const u8,
                children.items,
                {},
                struct {
                    pub fn cmp(_: void, a: []const u8, b: []const u8) bool { return std.mem.lessThan(u8, a, b); }
                }.cmp
            );
        }
        for (children.items) |c| {
            try buf.appendSlice(c);
            len = len + c.len;
        }
    } else {
        try buf.appendSlice(node.val);
        len = node.val.len;
    }
    const clen = try encodeLength(allocator, len);
    defer allocator.free(clen);
    try buf.insertSlice(0, clen);
    try buf.insert(0, @intFromEnum(node.tag));
    return try buf.toOwnedSlice();
}

pub fn encodeLength(allocator: std.mem.Allocator, len: u64) ![]u8 {
    if (len <= 127) {
        var buf = try allocator.alloc(u8, 1);
        buf[0] = @intCast(len);
        return buf;
    }
    var tmp = len;
    var num: u8 = 0;
    while (tmp != 0) : (tmp >>= 8) {
        num += 1;
    }
    var buf = try allocator.alloc(u8, 1 + num);
    buf[0] = 0x80 | num;
    for (0..num) |i| {
        const k :u6 = @truncate(i * 8);
        const val: u8 = @truncate((len >> k) & 0xFF);
        buf[num - i] = val;
    }
    return buf;
}

pub fn decodeValue(allocator: std.mem.Allocator, tag: Tag, val: []const u8) !Val {
    switch (tag) {
        .object_identifier => {
            var list = std.ArrayList(u64).init(allocator);
            defer list.deinit();

            const first = val[0];
            try list.append(@intCast(first / 40));
            try list.append(@intCast(first % 40));

            var i: usize = 1;
            while (i < val.len) {
                var v: u64 = 0;
                while (true) {
                    if (i >= val.len) return error.InvalidOid;
                    const byte = val[i];
                    v = (v << 7) | (byte & 0x7F);
                    i += 1;
                    if ((byte & 0x80) == 0) break;
                }
                try list.append(v);
            }
            var buffer: [128]u8 = undefined;
            var stream = std.io.fixedBufferStream(&buffer);
            var writer = stream.writer();
            try writer.print("{}", .{list.items[0]});
            for (list.items[1..]) |item| {
                try writer.print(".{}", .{item});
            }
            return .{ .string = try allocator.dupe(u8, stream.getWritten()) };
        },
        .integer => {
            var start: usize = 0;
            if (val[0] == 0x00 and val.len > 1 and (val[1] & 0x80) == 0) {
                start = 1;
            }
            var value: u64 = 0;
            for (val[start..]) |byte| {
                value = (value << 8) | byte;
            }
            return .{ .int = value };
        },
        .null => return .{ .null = {} },
        .boolean => return .{ .bool = std.mem.eql(u8, val, "\xFF") },
        .real_type => return error.NotSupported,
        else => return .{ .string = try allocator.dupe(u8, val) },
    }
}

pub fn encodeValue(allocator: std.mem.Allocator, tag: Tag, val: Val) ![]const u8 {
    switch (tag) {
        .boolean => {
            switch (val) {
                .bool => |b| {
                    if (b) {
                        return allocator.dupe(u8, "\xFF");
                    } else {
                        return allocator.dupe(u8, "\x00");
                    }
                },
                else => return error.InvalidType,
            }
        },
        .object_identifier => {
            switch (val) {
                .string => |s| {
                    var buf = std.mem.splitScalar(u8, s, '.');
                    var num = std.ArrayList(u64).init(allocator);
                    defer num.deinit();
                    var enc = std.ArrayList(u8).init(allocator);
                    defer enc.deinit();
                    while (buf.next()) |i| {
                        try num.append(try std.fmt.parseInt(u64, i, 10));
                    }
                    try enc.append(@intCast(40 * num.items[0] + num.items[1]));
                    for (num.items[2..]) |n| {
                        var tmp = std.ArrayList(u8).init(allocator);
                        defer tmp.deinit();
                        if (n == 0) {
                            try tmp.append(0);
                        } else {
                            var c = n;
                            while (c > 0) {
                                var t: u8 = @truncate(c & 0x7F);
                                if (c != n) {
                                    t |= 0x80;
                                }
                                try tmp.insert(0, t);
                                c >>= 7;
                            }
                        }
                        try enc.appendSlice(tmp.items);
                    }
                    return try enc.toOwnedSlice();
                },
                else => return error.InvalidType,
            }
        },
        .integer => {
            switch (val) {
                .int => |value| {
                    var tmp: [8]u8 = undefined;
                    std.mem.writeInt(u64, tmp[0..8], value, std.builtin.Endian.big);
                    var i: u8 = 0;
                    while (i < 7 and tmp[i] == 0) {
                        i += 1;
                    }
                    if (i > 0 and tmp[i] & 0x80 != 0) {
                        i -= 1;
                    }
                    var enc = std.ArrayList(u8).init(allocator);
                    defer enc.deinit();
                    try enc.appendSlice(tmp[i..]);
                    return enc.toOwnedSlice();
                },
                .string => |s| return allocator.dupe(u8, s),
                else => return error.InvalidType,
            }
        },
        .null => return "",
        .real_type => return error.NotSupported,
        else =>  {
            switch (val) {
                .string => |s| return allocator.dupe(u8, s),
                else => return error.InvalidType,
            }
        },
    }
}

test "integer value encode / decode" {
    const allocator = std.testing.allocator;
    const inp: Val = .{ .int = 64 };
    const der = try encodeValue(allocator, .integer, inp);
    defer allocator.free(der);
    const out = try decodeValue(allocator, .integer, der[0..]);
    defer if (out == .string) allocator.free(out.string);
    try std.testing.expectEqualDeep(inp, out);
}
