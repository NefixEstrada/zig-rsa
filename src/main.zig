const std = @import("std");
const hash = @import("hash.zig");

pub const PublicKey = struct {
    const This = @This();

    n: i64,
    e: i32,

    // The size is from the N
    const size = (@bitSizeOf(i64) + 7) / 8;
};

pub const PrivateKey = struct {
    n: i64,
    d: i64,
};

fn encrypt(pub_key: PublicKey, m: i64) !i64 {
    return try std.math.mod(i64, std.math.pow(i64, m, pub_key.e), pub_key.n);
}

fn decrypt(priv_key: PrivateKey, c: i64) !i64 {
    return try std.math.mod(i64, std.math.pow(i64, c, priv_key.d), priv_key.n);
}

fn incCounter(c: *[4]u8) void {
    c[3] += 1;
    if (c[3] != 0) return;

    c[2] += 1;
    if (c[2] != 0) return;

    c[1] += 1;
    if (c[1] != 0) return;

    c[0] += 1;
}

fn mgf1Xor(allocator: std.mem.Allocator, h: hash.Hash, out: []u8, seed: []const u8) std.mem.Allocator.Error!void {
    // Ensure the slice is initialized to 0
    var done: usize = 0;
    while (done < out.len) : (done += 1) {
        out[done] = 0;
    }

    var counter = std.mem.zeroes([4]u8);
    var digest = try allocator.alloc(u8, h.digest_length);
    defer allocator.free(digest);

    done = 0;
    while (done < out.len) {
        h.init();
        h.update(seed);
        h.update(counter[0..4]);
        h.final(digest);

        var i: u8 = 0;
        while (i < digest.len and done < out.len) : ({
            i += 1;
            done += 1;
        }) {
            out[done] ^= digest[i];
        }

        incCounter(&counter);
    }
}

test "mgf1XOR should work as expected" {
    {
        var h = hash.Sha1{};
        var out: [3]u8 = undefined;
        try mgf1Xor(std.testing.allocator, h.interface(), &out, &[_]u8{ 'f', 'o', 'o' });

        try std.testing.expectEqual([3]u8{ 26, 201, 7 }, out);
    }

    {
        var h = hash.Sha1{};
        var interface = h.interface();
        var out: [5]u8 = undefined;
        try mgf1Xor(std.testing.allocator, interface, &out, &[_]u8{ 'f', 'o', 'o' });

        try std.testing.expectEqual([5]u8{ 26, 201, 7, 92, 212 }, out);
    }
}

pub fn fillBytes(out: []u8) void {
    // Ensure the slice is initialized to 0
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        out[i] = 0;
    }
}

const encryptError = error{
    MessageTooLong,
};

pub fn encryptOaep(allocator: std.mem.Allocator, h: hash.Hash, random: std.rand.Random, pub_key: PublicKey, msg: []const u8, label: []u8) ![]const u8 {
    // TODO: Check pub
    const k = PublicKey.size;

    if (msg.len > k - 2 * h.digest_length - 2) {
        return encryptError.MessageTooLong;
    }

    // var l_hash = try allocator.alloc(u8, h.digest_length);
    var l_hash = try allocator.alloc(u8, h.digest_length);
    defer allocator.free(l_hash);

    h.hash(label, l_hash);

    var em: [k]u8 = undefined;
    var seed = em[1 .. 1 + h.digest_length];
    var db = em[1 + h.digest_length ..];

    std.mem.copy(u8, db[0..h.digest_length], l_hash[0..]);
    db[db.len - msg.len - 1] = 1;
    std.mem.copy(u8, db[db.len - msg.len ..], msg);

    random.bytes(seed);

    try mgf1Xor(allocator, h, db, seed);
    try mgf1Xor(allocator, h, seed, db);

    _ = try encrypt(pub_key, std.mem.bytesToValue(i64, &em));

    const out = [_]u8{};
    // return fillBytes(&c);
    return out[0..];
}

test "encryptOaep should work as expected" {
    {
        var h = hash.Sha1{};
        // encryptOaep(std.testing.allocator, h.interface(), std.rand.DefaultPrng, pub_key: PublicKey, msg: []const u8, label: []u8)
    }
}

comptime {
    std.testing.refAllDecls(@This());
}
