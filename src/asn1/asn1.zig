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
    bit_string_constructed = 3 | @backingInt(Type.constructed),
    octet_string_constructed = 4 | @backingInt(Type.constructed),
    sequence = 16 | @backingInt(Type.constructed),
    set = 17 | @backingInt(Type.constructed),
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
        return @backingInt(self) & @backingInt(Type.constructed) != 0;
    }
    pub fn isLong(self: Tag) bool {
        return @backingInt(self) & 0b00011111 == 31;
    }
    pub fn val(self: *const Tag) u8 {
        return @backingInt(self) & 0b00011111;
    }
    pub fn class(self: *const Tag) Class {
        const tmp = @backingInt(self);
            if (tmp & @backingInt(Class.application) == @backingInt(Class.application)) {
            return Class.application;
        }
        if (tmp & @backingInt(Class.private) == @backingInt(Class.private)) {
            return Class.private;
        }
        if (tmp & @backingInt(Class.context) == @backingInt(Class.context)) {
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
            .nodes = nodes orelse .empty,
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
        var node_list: std.ArrayList(*Node) = .empty;
        try node_list.appendSlice(allocator, nodes);
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
        const new_tag = @backingInt(tag) | @backingInt(Tag.Type.constructed);
        var node_list: std.ArrayList(*Node) = .empty;
        try node_list.appendSlice(allocator, nodes);
        var node = try Node.init(allocator, @fromBackingInt(new_tag), "", node_list);
        node.imp = imp;
        return node;
    }
    pub fn implicitFromValue(
        allocator: std.mem.Allocator,
        tag: Tag,
        imp: Tag,
        val: Val,
    ) !*Node {
        var new_tag = @backingInt(tag);
        if (imp.isConstructed()) {
            new_tag |= @backingInt(Tag.Type.constructed);
        }
        var node = try Node.init(allocator, @fromBackingInt(new_tag), try encodeValue(allocator, imp, val), null);
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
        self.nodes.deinit(self.allocator);
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
    var nodes: std.ArrayList(*Node) = .empty;
    var pos: usize = 0;
    while (pos < buf.len) {
        var tmp: u8 = undefined;

        // parse tag
        const tag = buf[pos];
        pos += 1;
        if (pos >= buf.len) break;
        if ((tag & 31) == 31) { // long tags are not supported but at least parse them
            while (true) {
                tmp = buf[pos];
                pos += 1;
                if (pos >= buf.len) break;
                if (tmp & 128 == 0) {
                    break;
                }
            }
        }

        var beg: u64 = 0;
        var end: u64 = 0;
        var len: u64 = 0;

        // parse length
        tmp = buf[pos];
        pos += 1;
        if (pos >= buf.len) break;
        if (tmp == 128) {
            beg = pos;
            while (true) {
                tmp = buf[pos];
                pos += 1;
                if (pos >= buf.len) break;
                if (tmp == 0) {
                    tmp = buf[pos];
                    pos += 1;
                    if (pos >= buf.len) break;
                    if (tmp == 0) {
                        break;
                    }
                }
            }
            end = pos - 2;
            len = pos - beg;
            pos = beg;
        } else if (tmp & 128 == 128) {
            for (0..(tmp & 127)) |_| {
                tmp = buf[pos];
                pos += 1;
                if (pos >= buf.len) break;
                len <<= 8;
                len |= tmp;
            }
            beg = pos;
            end = beg + len;
        } else {
            len = tmp;
            beg = pos;
            end = beg + len;
        }

        // create node
        const node = try Node.init(allocator, @fromBackingInt(tag), buf[beg..end], null);
        if (node.tag.isConstructed()) {
            node.nodes = try decode(allocator, buf[beg..end]);
        }
        try nodes.append(allocator, node);
        pos = beg + len;
    }
    return nodes;
}

pub fn encode(allocator: std.mem.Allocator, node: *Node) ![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    var len: u64 = 0;
    if (node.tag.isConstructed() and node.nodes.items.len > 0) {
        var children: std.ArrayList([]const u8) = .empty;
        defer {
            for (children.items) |c| {
                allocator.free(c);
            }
            children.deinit(allocator);
        }
        for (node.nodes.items) |n| {
            const val = try encode(allocator, n);
            try children.append(allocator, val);
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
            try buf.appendSlice(allocator, c);
            len = len + c.len;
        }
    } else {
        try buf.appendSlice(allocator, node.val);
        len = node.val.len;
    }
    const clen = try encodeLength(allocator, len);
    defer allocator.free(clen);
    try buf.insertSlice(allocator, 0, clen);
    try buf.insert(allocator, 0, @backingInt(node.tag));
    return try buf.toOwnedSlice(allocator);
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
            var list: std.ArrayList(u64) = .empty;
            defer list.deinit(allocator);

            const first = val[0];
            try list.append(allocator, @intCast(first / 40));
            try list.append(allocator, @intCast(first % 40));

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
                try list.append(allocator, v);
            }
            var buffer: [128]u8 = undefined;
            var writer: std.Io.Writer = .fixed(&buffer);
            try writer.print("{}", .{list.items[0]});
            for (list.items[1..]) |item| {
                try writer.print(".{}", .{item});
            }
            const string = try allocator.dupe(u8, buffer[0..writer.end]);
            return .{
                .string = string,
            };
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
                    var num: std.ArrayList(u64) = .empty;
                    defer num.deinit(allocator);
                    var enc: std.ArrayList(u8) = .empty;
                    defer enc.deinit(allocator);
                    while (buf.next()) |i| {
                        try num.append(allocator, try std.fmt.parseInt(u64, i, 10));
                    }
                    try enc.append(allocator, @intCast(40 * num.items[0] + num.items[1]));
                    for (num.items[2..]) |n| {
                        var tmp: std.ArrayList(u8) = .empty;
                        defer tmp.deinit(allocator);
                        if (n == 0) {
                            try tmp.append(allocator, 0);
                        } else {
                            var c = n;
                            while (c > 0) {
                                var t: u8 = @truncate(c & 0x7F);
                                if (c != n) {
                                    t |= 0x80;
                                }
                                try tmp.insert(allocator, 0, t);
                                c >>= 7;
                            }
                        }
                        try enc.appendSlice(allocator, tmp.items);
                    }
                    return try enc.toOwnedSlice(allocator);
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
                    var enc: std.ArrayList(u8) = .empty;
                    defer enc.deinit(allocator);
                    try enc.appendSlice(allocator, tmp[i..]);
                    return enc.toOwnedSlice(allocator);
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
