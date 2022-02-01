const asn1 = @import("../asn1.zig");

pub const AlgorithmIdentifier = struct {
    algorithm: asn1.ObjectIdentifier,
    parameters: ?asn1.RawValue,
};
