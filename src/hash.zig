const std = @import("std");

pub fn Hash(
    comptime Context: type,
    comptime digest_length: u8,
    comptime hashFn: fn ([]const u8, *[digest_length]u8) void,
    comptime updateFn: fn (Context, []const u8) void,
    comptime finalFn: fn (Context, *[digest_length]u8) void,
    comptime resetFn: fn (Context) void,
) type {
    return struct {
        const This = @This();

        context: Context,

        pub const digest_length = digest_length;

        pub fn hash(b: []const u8, out: *[digest_length]u8) void {
            return hashFn(b, out);
        }

        pub fn update(this: This, b: []const u8) void {
            return updateFn(this.context, b);
        }

        pub fn final(this: This, out: *[digest_length]u8) void {
            return finalFn(this.context, out);
        }

        pub fn reset(this: This) void {
            return resetFn(this.context);
        }
    };
}

pub fn isHash(comptime T: type) void {
    comptime {
        if (!(std.meta.trait.multiTrait(.{
            std.meta.trait.hasFn("hash"),
            std.meta.trait.hasFn("update"),
            std.meta.trait.hasFn("final"),
            std.meta.trait.hasFn("reset"),
        })(T) and std.meta.trait.hasDecls(T, .{"digest_length"}))) @compileError("Hash type doesn't implement the interface correctly");
    }
}

pub const Sha1 = struct {
    const This = @This();

    const digest_length = std.crypto.hash.Sha1.digest_length;

    pub const HashType = Hash(*This, digest_length, hashFn, updateFn, finalFn, resetFn);

    h: std.crypto.hash.Sha1 = std.crypto.hash.Sha1.init(.{}),

    pub fn hash(this: *This) HashType {
        return .{ .context = this };
    }

    fn hashFn(b: []const u8, out: *[digest_length]u8) void {
        std.crypto.hash.Sha1.hash(b, out, .{});
    }

    fn updateFn(this: *This, b: []const u8) void {
        return this.h.update(b);
    }

    fn finalFn(this: *This, out: *[digest_length]u8) void {
        return this.h.final(out);
    }

    fn resetFn(this: *This) void {
        this.h = std.crypto.hash.Sha1.init(.{});
    }
};

comptime {
    std.testing.refAllDecls(@This());
}
