const std = @import("std");

pub const Hash = struct {
    const This = @This();

    impl: *anyopaque,
    initFn: fn (*anyopaque) void,
    hashFn: fn ([]const u8, []u8) void,
    updateFn: fn (*anyopaque, []const u8) void,
    finalFn: fn (*anyopaque, []u8) void,

    digest_length: u8,

    pub fn init(iface: *const This) void {
        iface.initFn(iface.impl);
    }

    pub fn hash(iface: *const This, b: []const u8, out: []u8) void {
        return iface.hashFn(b, out);
    }

    pub fn update(iface: *const This, b: []const u8) void {
        return iface.updateFn(iface.impl, b);
    }

    pub fn final(iface: *const This, out: []u8) void {
        return iface.finalFn(iface.impl, out);
    }
};

pub const Sha1 = struct {
    const This = @This();

    hash: std.crypto.hash.Sha1 = std.crypto.hash.Sha1.init(.{}),

    pub fn init() This {
        return This{};
    }

    pub fn interface(this: *This) Hash {
        return .{
            .impl = @ptrCast(*anyopaque, this),
            .initFn = initFn,
            .hashFn = hashFn,
            .updateFn = updateFn,
            .finalFn = finalFn,
            .digest_length = std.crypto.hash.Sha1.digest_length,
        };
    }

    fn initFn(this_anyopaque: *anyopaque) void {
        var this = @ptrCast(*This, @alignCast(@alignOf(This), this_anyopaque));

        this.hash = std.crypto.hash.Sha1.init(.{});
    }

    fn hashFn(b: []const u8, out: []u8) void {
        std.crypto.hash.Sha1.hash(b, out[0..std.crypto.hash.Sha1.digest_length], .{});
    }

    fn updateFn(this_anyopaque: *anyopaque, b: []const u8) void {
        var this = @ptrCast(*This, @alignCast(@alignOf(This), this_anyopaque));

        return this.hash.update(b);
    }

    fn finalFn(this_anyopaque: *anyopaque, out: []u8) void {
        var this = @ptrCast(*This, @alignCast(@alignOf(This), this_anyopaque));

        return this.hash.final(out[0..std.crypto.hash.Sha1.digest_length]);
    }
};

comptime {
    std.testing.refAllDecls(@This());
}
