const std = @import("std");
const asn1 = @import("../asn1.zig");
const pkix = @import("pkix.zig");
const pkcs1 = @import("pkcs1.zig");
const rsa = @import("../rsa.zig");

const PublicKeyInfo = struct {
    raw: asn1.RawContent,
    algorithm: pkix.AlgorithmIdentifier,
    pub_key: asn1.BitString,
};

const PublicKey = union {
    rsa: rsa.PublicKey,
};

pub fn parsePkixPublicKey(allocator: std.mem.Allocator, der: []const u8) !PublicKey {
    const pki = x: {
        var stream = asn1.TokenStream.init(der);
        const res = try asn1.parse(PublicKeyInfo, &stream, .{ .allocator = allocator });
        break :x res;
    };

    const algo = getPublicKeyAlgorithmFromOID(pki.algorithm.algorithm);

    return try parsePublicKey(allocator, algo, pki);
}

test "parsePkixPublicKey should work as expected" {
    const pem_decoded_pub_key = &[_]u8{ 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 221, 90, 15, 55, 211, 202, 82, 50, 133, 44, 204, 14, 129, 238, 190, 194, 112, 226, 242, 198, 196, 76, 98, 49, 216, 82, 151, 26, 10, 173, 0, 170, 115, 153, 233, 185, 222, 68, 70, 17, 8, 60, 89, 234, 145, 154, 157, 118, 194, 10, 123, 225, 49, 169, 144, 69, 236, 25, 167, 187, 69, 45, 100, 122, 114, 66, 158, 102, 184, 126, 40, 190, 158, 129, 135, 237, 29, 42, 42, 1, 239, 62, 178, 54, 7, 6, 189, 135, 59, 7, 242, 209, 241, 167, 35, 55, 170, 181, 236, 148, 233, 131, 227, 145, 7, 245, 44, 72, 13, 64, 73, 21, 232, 77, 117, 163, 219, 44, 253, 96, 23, 38, 161, 40, 203, 29, 127, 17, 73, 45, 75, 219, 83, 39, 46, 101, 34, 118, 102, 114, 32, 121, 92, 112, 155, 138, 155, 74, 246, 72, 156, 191, 72, 187, 129, 115, 184, 251, 96, 124, 131, 74, 113, 182, 232, 191, 45, 106, 171, 130, 175, 60, 138, 215, 206, 22, 216, 220, 245, 131, 115, 166, 237, 196, 39, 247, 72, 77, 9, 116, 77, 76, 8, 244, 225, 158, 208, 122, 219, 246, 203, 49, 36, 59, 197, 208, 209, 20, 94, 119, 160, 138, 111, 197, 239, 210, 8, 236, 166, 125, 106, 191, 45, 111, 56, 245, 139, 111, 221, 124, 40, 119, 79, 176, 204, 3, 252, 73, 53, 198, 224, 116, 132, 45, 46, 20, 121, 211, 216, 120, 114, 73, 37, 135, 25, 249, 2, 3, 1, 0, 1 };

    {
        const pub_key = try parsePkixPublicKey(std.testing.allocator, pem_decoded_pub_key);

        try std.testing.expectEqual(rsa.PublicKey, @TypeOf(pub_key));
    }
}

const parseRsaPublicKey = error{
    MissingNullParameters,
    InvalidPublicKey,
    InvalidModulus,
    InvalidPublicExponent,
    ModulusNotPositive,
    ExponentNotPositive,
};

pub fn parsePublicKey(allocator: std.mem.Allocator, algo: PublicKeyAlgorithm, keyData: PublicKeyInfo) !PublicKey {
    switch (algo) {
        .Rsa => {
            if (!std.mem.eql(u8, keyData.algorithm.parameters.?.full_buf.?, asn1.nullBytes[0..])) return parseRsaPublicKey.MissingNullParameters;

            var p = pkcs1.Pkcs1PublicKey{
                .n = try std.math.big.int.Managed.init(allocator),
                .e = 0,
            };

            if (!p.n.isPositive()) return parseRsaPublicKey.ModulusNotPositive;
            if (p.e <= 0) return parseRsaPublicKey.ExponentNotPositive;

            return PublicKey{ .rsa = rsa.PublicKey{
                .n = p.n,
                .e = p.e,
            } };
        },
    }
}

const PublicKeyAlgorithm = enum {
    Rsa,
};

var t = [_]i32{ 1, 2, 840, 113549, 1, 1, 1 };
const oidPublicKeyRsa = asn1.ObjectIdentifier{
    .object_identifier = t[0..],
};

pub fn getPublicKeyAlgorithmFromOID(oid: asn1.ObjectIdentifier) PublicKeyAlgorithm {
    if (std.mem.eql(i32, oid.object_identifier, oidPublicKeyRsa.object_identifier)) {
        return .Rsa;
    }

    // TODO: This should be an error
    @panic("unknown algorithm!");
}
