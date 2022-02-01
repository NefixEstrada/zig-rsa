const std = @import("std");

pub const Pkcs1PublicKey = struct {
    n: std.math.big.int.Managed,
    e: i32,
};
