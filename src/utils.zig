const std = @import("std");
const Managed = std.math.big.int.Managed;

pub fn powMod(x: Managed, y: Managed, m: std.math.big.int.Const) anyerror!Managed {
    if (m.eqZero()) {
        return error.DivideByZero;
    }

    var one = try Managed.init(x.allocator);
    defer one.deinit();
    try one.set(1);

    if (y.eq(one)) {
        var temp = try Managed.init(x.allocator);
        defer temp.deinit();

        var result = try Managed.init(x.allocator);
        try temp.divTrunc(&result, x.toConst(), m.abs());

        return result;
    }

    var temp = try Managed.init(x.allocator);
    defer temp.deinit();

    var two = try Managed.init(x.allocator);
    defer two.deinit();
    try two.set(2);

    var y_half = try Managed.init(x.allocator);
    defer y_half.deinit();
    try y_half.divTrunc(&temp, y.toConst(), two.toConst());

    var r = try powMod(x, y_half, m);
    try r.sqr(r.toConst());
    try temp.divFloor(&r, r.toConst(), m);

    try temp.bitAnd(y, one);
    if (temp.eq(one)) {
        // This allocation is done in order to not overflow the big int :)
        var temp2 = try Managed.init(x.allocator);
        defer temp2.deinit();

        try temp2.mul(r.toConst(), x.toConst());
        try r.copy(temp2.toConst());

        try temp.divTrunc(&r, r.toConst(), m);
    }

    return r;
}

test "powMod should work" {
    var x = try Managed.init(std.testing.allocator);
    defer x.deinit();
    try x.set(2);

    var y = try Managed.init(std.testing.allocator);
    defer y.deinit();
    try y.set(99999999);

    var z = try Managed.init(std.testing.allocator);
    defer z.deinit();
    try z.set(147);

    var res = try powMod(x, y, z.toConst());
    defer res.deinit();

    try std.testing.expectEqual(@as(u8, 134), try res.to(u8));
}

pub fn setBytes(allocator: std.mem.Allocator, int: *Managed, buf: []u8) !void {
    var hex = try allocator.alloc(u8, buf.len * 2);
    defer allocator.free(hex);

    const chars = [_]u8{ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    for (buf) |b, i| {
        hex[i * 2 + 0] = chars[b >> 4];
        hex[i * 2 + 1] = chars[b & 0x0f];
    }

    try int.setString(16, hex);
}

pub fn toBytes(allocator: std.mem.Allocator, int: Managed) ![]u8 {
    var hex = try int.toString(allocator, 16, .lower);
    defer allocator.free(hex);

    var out: []u8 = undefined;

    if (hex.len & 1 == 0) {
        out = try allocator.alloc(u8, hex.len / 2);
        errdefer allocator.free(out);

        _ = try std.fmt.hexToBytes(out, hex);
    } else {
        out = try allocator.alloc(u8, (hex.len + 1) / 2);
        errdefer allocator.free(out);

        out[0] = try std.fmt.charToDigit(hex[0], 16);
        _ = try std.fmt.hexToBytes(out[1..], hex[1..]);
    }

    return out;
}

pub fn constantTimeCompare(x: []const u8, y: []const u8) usize {
    if (std.mem.eql(u8, x, y)) return 1;
    return 0;
}

test "constantTimeCompare should work as expected" {
    {
        const expected: usize = 1;
        const compare = constantTimeCompare(&[_]u8{}, &[_]u8{});
        try std.testing.expectEqual(expected, compare);
    }
    {
        const expected: usize = 1;
        const compare = constantTimeCompare(&[_]u8{0x11}, &[_]u8{0x11});
        try std.testing.expectEqual(expected, compare);
    }
    {
        const expected: usize = 0;
        const compare = constantTimeCompare(&[_]u8{0x12}, &[_]u8{0x11});
        try std.testing.expectEqual(expected, compare);
    }
    {
        const expected: usize = 0;
        const compare = constantTimeCompare(&[_]u8{0x11}, &[_]u8{0x12});
        try std.testing.expectEqual(expected, compare);
    }
    {
        const expected: usize = 0;
        const compare = constantTimeCompare(&[_]u8{ 0x11, 0x12 }, &[_]u8{0x11});
        try std.testing.expectEqual(expected, compare);
    }
}

pub fn constantTimeSelect(v: usize, x: usize, y: usize) usize {
    if (v == 0) return y;
    if (v == 1) return x;

    unreachable;
}

pub fn constantTimeByteEq(x: u8, y: u8) usize {
    if (x == y) return 1;
    return 0;
}

test "constantTimeByteEq should work as expected" {
    {
        const expected: usize = 1;
        const compare = constantTimeByteEq(0, 0);
        try std.testing.expectEqual(expected, compare);
    }
    {
        const expected: usize = 0;
        const compare = constantTimeByteEq(0, 1);
        try std.testing.expectEqual(expected, compare);
    }
    {
        const expected: usize = 0;
        const compare = constantTimeByteEq(1, 0);
        try std.testing.expectEqual(expected, compare);
    }
    {
        const expected: usize = 1;
        const compare = constantTimeByteEq(0xff, 0xff);
        try std.testing.expectEqual(expected, compare);
    }
    {
        const expected: usize = 0;
        const compare = constantTimeByteEq(0xff, 0xfe);
        try std.testing.expectEqual(expected, compare);
    }
}
