const std = @import("std");

const tagBoolean: i32 = 1;
const tagInteger: i32 = 2;
const tagBitString: i32 = 3;
const tagOctetString: i32 = 4;
const tagNull: i32 = 5;
const tagOid: i32 = 6;
const tagEnum: i32 = 10;
const tagUtf8String: i32 = 12;
const tagSequence: i32 = 16;
const tagSet: i32 = 17;
const tagNumericString: i32 = 18;
const tagPrintableString: i32 = 19;
const tagT61String: i32 = 20;
const tagIa5String: i32 = 22;
const tagUtcTime: i32 = 23;
const tagGeneralizedTime: i32 = 24;
const tagGeneralizedString: i32 = 27;
const tagBmpString: i32 = 30;

const classUniversal: i32 = 0;
const classApplication: i32 = 1;
const classContextSpecific: i32 = 2;
const classPrivate: i32 = 3;

const TagAndLength = struct {
    class: i32,
    tag: i32,
    length: usize,
    is_compound: bool,
};

pub const BitString = struct {
    bytes: []const u8,
    bit_length: usize,
};

pub const nullBytes = [_]u8{ tagNull, 0 };

pub const ObjectIdentifier = struct { object_identifier: []i32 };

pub const Enumerated = struct {
    enumerated: i32,
};

pub const Flag = struct { flag: bool };

pub const RawValue = struct {
    class: i32,
    tag: i32,
    is_compound: i32,
    bytes: []const u8,
    full_bytes: ?[]const u8,
};

pub const RawContent = struct { raw_content: []const u8 };

pub const StreamingParser = struct {
    const This = @This();

    state: State,
    after_value_state: State,
    complete: bool,

    tag_and_length_class: i32,
    tag_and_length_tag: i32,
    tag_and_length_is_compound: bool,
    tag_and_length_length: i32,
    tag_and_length_num_bytes: i32,

    int_base_128: i32,
    int_base_128_val: i64,
    int_base_128_shifted: usize,

    int_64_val: i64,
    int_64_shifted: usize,

    pub fn init() This {
        var p: This = undefined;
        p.reset();
        return p;
    }

    pub fn reset(this: *This) void {
        this.state = .TagAndLength;
        this.after_value_state = .End;
        this.complete = false;

        this.tag_and_length_class = 0;
        this.tag_and_length_tag = 0;
        this.tag_and_length_is_compound = false;
        this.tag_and_length_length = 0;
        this.tag_and_length_num_bytes = 0;

        this.int_base_128 = 0;
        this.int_base_128_val = 0;
        this.int_base_128_shifted = 0;

        this.int_64_val = 0;
        this.int_64_shifted = 0;
    }

    pub const State = enum {
        TagAndLength,
        TagAndLengthBottomBits,
        TagAndLengthLength1,
        TagAndLengthLength2,
        IntBase128,
        Int64,
        BitString,
        BigInt,
        Bool,
        End,
    };

    pub const Error = error{
        IndefiniteLengthNotDer,
        LengthTooLarge,
        SuperfluousLeadingLengthZeroes,
        NoMinimalLength,
        Base128IntegerTooLarge,
    };

    pub fn feed(this: *This, c: u8, field: *?Field) Error!void {
        field.* = null;

        var loop = true;
        while (loop) {
            loop = try this.transition(c, field);

            if (loop) {
                var field2: ?Field = field.*;
                loop = try this.transition(c, &field2);

                if (!std.meta.eql(field.*, field2)) {
                    field.* = field2;
                } else {
                    field.* = null;
                }
            }
        }
    }

    fn transition(this: *This, c: u8, field: *?Field) Error!bool {
        switch (this.state) {
            .TagAndLength => {
                this.tag_and_length_class = c >> 6;
                this.tag_and_length_tag = c & 0x1f;
                this.tag_and_length_is_compound = c & 0x20 == 0x20;

                if (this.tag_and_length_tag == 0x1f) {
                    this.after_value_state = .TagAndLengthBottomBits;
                    this.state = .IntBase128;
                } else this.state = .TagAndLengthLength1;
            },
            .TagAndLengthBottomBits => {
                this.tag_and_length_tag = field.*.?.IntBase128;

                if (this.tag_and_length_tag < 0x1f) return Error.NoMinimalLength;

                this.after_value_state = .End;
                this.state = .TagAndLengthLength1;
            },
            .TagAndLengthLength1 => {
                this.tag_and_length_num_bytes = c & 0x7f;

                if (c & 0x80 == 0) {
                    this.tag_and_length_length = this.tag_and_length_num_bytes;
                    this.complete = true;

                    field.* = .{ .TagAndLength = .{
                        .class = this.tag_and_length_class,
                        .tag = this.tag_and_length_tag,
                        .length = @intCast(usize, this.tag_and_length_length),
                        .is_compound = this.tag_and_length_is_compound,
                    } };
                    return false;
                }

                if (this.tag_and_length_num_bytes == 0) {
                    return Error.IndefiniteLengthNotDer;
                }

                this.tag_and_length_length = 0;
                this.state = .TagAndLengthLength2;
            },
            .TagAndLengthLength2 => {
                if (this.tag_and_length_length >= 1 << 23) return Error.LengthTooLarge;

                this.tag_and_length_length <<= 8;
                this.tag_and_length_length |= c;

                if (this.tag_and_length_length == 0) return Error.SuperfluousLeadingLengthZeroes;

                this.tag_and_length_num_bytes -= 1;
                if (this.tag_and_length_num_bytes == 0) {
                    if (this.tag_and_length_length < 0x80) return Error.NoMinimalLength;

                    this.complete = true;
                    field.* = .{ .TagAndLength = .{
                        .class = this.tag_and_length_class,
                        .tag = this.tag_and_length_tag,
                        .length = @intCast(usize, this.tag_and_length_length),
                        .is_compound = this.tag_and_length_is_compound,
                    } };
                }
            },
            .IntBase128 => {
                if (this.int_base_128_shifted == 5) return Error.Base128IntegerTooLarge;

                this.int_base_128_val <<= 7;

                if (this.int_base_128_shifted == 0 and c == 0x80) return Error.NoMinimalLength;

                this.int_base_128_val |= @intCast(i64, c & 0x7f);

                if (c & 0x80 == 0) {
                    if (this.int_base_128_val > std.math.maxInt(i32)) {
                        return Error.Base128IntegerTooLarge;
                    }

                    this.complete = this.after_value_state == .End;
                    this.state = this.after_value_state;
                    field.* = .{ .IntBase128 = @intCast(i32, this.int_base_128_val) };

                    if (this.after_value_state != .End) {
                        return true;
                    }
                }

                this.int_base_128_shifted += 1;
            },
            .Int64 => {
                @panic("not implemented!");
            },
            .BitString => {
                @panic("not implemented!");
            },
            .BigInt => {
                @panic("not implemented!");
            },
            .Bool => {
                @panic("not implemented!");
            },
            else => unreachable,
        }

        return false;
    }
};

pub const Field = union(enum) {
    TagAndLength: TagAndLength,
    IntBase128: i32,
    Int64: i64,
    BigInt: std.math.big.int.Managed,
    BitString: BitString,
    ObjectIdentifier: ObjectIdentifier,
};

pub const FieldStream = struct {
    const This = @This();

    i: usize,
    buf: []const u8,
    field: ?Field,
    parser: StreamingParser,

    pub const Error = StreamingParser.Error || error{UnexpectedEndOfAsn1};

    pub fn init(buf: []const u8) This {
        return This{
            .i = 0,
            .buf = buf,
            .parser = StreamingParser.init(),
            .field = null,
        };
    }

    pub fn next(this: *This) Error!?Field {
        if (this.field) |field| {
            this.field = null;

            return field;
        }

        var f: ?Field = undefined;

        while (this.i < this.buf.len) {
            try this.parser.feed(this.buf[this.i], &f);
            this.i += 1;

            if (f) |field| {
                return field;
            }
        }

        if (f) |field| {
            return field;
        } else if (this.parser.complete) {
            return null;
        } else {
            return error.UnexpectedEndOfAsn1;
        }
    }
};

const UniversalType = struct {
    match_any: bool,
    tag: i32,
    is_compound: bool,
};

const UniversalTypeError = error{UnknownType};

fn getUniversalType(comptime T: type) UniversalTypeError!UniversalType {
    switch (T) {
        RawValue => return UniversalType{ .match_any = true, .tag = -1, .is_compound = false },
        ObjectIdentifier => return UniversalType{ .match_any = false, .tag = tagOid, .is_compound = false },
        BitString => return UniversalType{ .match_any = false, .tag = tagBitString, .is_compound = false },
        // TODO: .Time => return .{ .match_any = false, .tag = tagUtcTime, .is_compound = false },
        Enumerated => return UniversalType{ .match_any = false, .tag = tagEnum, .is_compound = false },
        std.math.big.int.Managed => return UniversalType{ .match_any = false, .tag = tagInteger, .is_compound = false },
        else => {},
    }

    switch (@typeInfo(T)) {
        .Bool => return UniversalType{ .match_any = false, .tag = tagBoolean, .is_compound = false },
        .Int => return UniversalType{ .match_any = false, .tag = tagInteger, .is_compound = false },
        .Struct => return UniversalType{ .match_any = false, .tag = tagSequence, .is_compound = true },
        .Pointer => |ptr_info| {
            if (ptr_info.size == .Slice) {
                const child_info = @typeInfo(ptr_info.child);

                switch (child_info) {
                    .Int => |int| {
                        // TODO: How should we distinguish from bytes and strings? Can we?
                        if (int.signedness == .unsigned and int.bits == 8) {
                            return UniversalType{ .match_any = false, .tag = tagSequence, .is_compound = true };
                        }

                        // TODO: SET
                    },
                    else => {},
                }
            }

            return UniversalTypeError.UnknownType;
        },
        else => return UniversalTypeError.UnknownType,
    }
}

pub const ParseOptions = struct {
    optional: bool = false,
    explicit: bool = false,
    application: bool = false,
    private: bool = false,
    default_value: ?i64 = null,
    tag: ?i32 = null,
    string_type: i32 = 0,
    time_type: i32 = 0,
    set: bool = false,
    omit_empty: bool = false,
};

fn ParseInternalError(comptime _: type) type {
    // TODO: This should be actually good
    return UniversalTypeError || FieldStream.Error || error{UnexpectedField} || std.mem.Allocator.Error;
}

// Missing errors:
// ZeroLengthExplicitTagNotAFlag

pub fn parseInternal(allocator: std.mem.Allocator, comptime T: type, field: Field, fields: *FieldStream, options: ParseOptions) ParseInternalError(T)!T {
    // TODO: This v
    const t = field.TagAndLength;

    var internal_fields = FieldStream.init(fields.buf[fields.i .. fields.i + t.length]);
    // if (!t.is_compound and t.class == classUniversal) {
    //     @panic("aaaaaaaaaaa");
    // }

    if (options.explicit) {
        var expected_class = classContextSpecific;
        if (options.application) expected_class = classApplication;

        // TODO: This is done because the compiler breaks if it's in one line. See #6059 for more info
        if (options.tag != null) {
            if (t.class == expected_class and t.tag == options.tag.? and (t.length == 0 or t.is_compound)) {
                if (T == RawValue) {
                    // The inner element should not be parsed for RawValues.
                } else if (t.length > 0) {
                    // TODO: Parse tag and length (again!)
                    @panic("aaaaa");
                } else {
                    if (T != Flag) {
                        @panic("aaaa");
                    }

                    return true;
                }
            } else {
                @panic("aaa");
            }
        }
    }

    var universal_type = try getUniversalType(T);

    if (universal_type.tag == tagPrintableString) {
        if (t.class == classUniversal) {
            switch (t.tag) {
                tagIa5String, tagGeneralizedString, tagT61String, tagUtf8String, tagNumericString, tagBmpString => universal_type.tag = t.tag,
                else => {},
            }
        } else if (options.string_type != 0) universal_type.tag = options.string_type;
    }

    if (universal_type.tag == tagUtcTime and t.tag == tagGeneralizedTime and t.class == classUniversal) universal_type.tag = tagGeneralizedTime;

    if (options.set) universal_type.tag = tagSet;

    var match_any_class_and_tag = universal_type.match_any;
    var expected_class = classUniversal;
    var expected_tag = universal_type.tag;

    if (!options.explicit and options.tag != null) {
        expected_class = classContextSpecific;
        expected_tag = options.tag.?;
        match_any_class_and_tag = false;
    }

    if (!options.explicit and options.application and options.tag != null) {
        expected_class = classApplication;
        expected_tag = options.tag.?;
        match_any_class_and_tag = false;
    }

    if (!options.explicit and options.private and options.tag != null) {
        expected_class = classPrivate;
        expected_tag = options.tag.?;
        match_any_class_and_tag = false;
    }

    std.debug.print("+++===========+\n", .{});
    std.debug.print("{}\n", .{t});
    std.debug.print("{}\n", .{getUniversalType(T)});
    std.debug.print("{b}\n", .{match_any_class_and_tag});
    std.debug.print("{d}\n", .{expected_class});
    std.debug.print("{d}\n", .{expected_tag});
    std.debug.print("+++===========+\n", .{});
    if (!match_any_class_and_tag and (t.class != expected_class or t.tag != expected_tag) or (!universal_type.match_any and t.is_compound != universal_type.is_compound)) {
        @panic("aaa");
    }

    // TODO: invalid length!

    // TODO: Offset!

    if (T == RawValue) {
        return RawValue{
            .class = t.class,
            .tag = t.tag,
            .is_compound = t.is_compound,
            // TODO: This should be counting from the init offset!
            .bytes = internal_fields.buf[0..],
        };
    }

    if (T == RawContent) {
        return RawContent{
            .raw_content = internal_fields.buf[0..],
        };
    }

    if (T == ObjectIdentifier) {
        var object_identifier = try allocator.alloc(i32, internal_fields.buf.len + 1);
        var v: i32 = undefined;
        internal_fields.parser.state = .IntBase128;
        switch ((try internal_fields.next()) orelse @panic("aaa")) {
            .IntBase128 => |int| v = int,
            else => return error.UnexpectedField,
        }

        if (v < 80) {
            object_identifier[0] = @divFloor(v, 40);
            object_identifier[1] = @mod(v, 40);
        } else {
            object_identifier[0] = 2;
            object_identifier[1] = v - 80;
        }

        var i: usize = 2;
        while (internal_fields.i < internal_fields.buf.len) : (i += 1) {
            internal_fields.parser.state = .IntBase128;
            switch ((try internal_fields.next()) orelse @panic("aaa")) {
                .IntBase128 => |int| v = int,
                else => return error.UnexpectedField,
            }

            object_identifier[i] = v;
        }

        return ObjectIdentifier{
            .object_identifier = object_identifier[0..i],
        };
    }

    if (T == BitString) {
        fields.parser.state = .BitString;
        switch ((try fields.next()) orelse @panic("aaa")) {
            .BitString => |bit_string| return bit_string,
            else => return error.UnexpectedField,
        }
    }

    // TODO: Time!

    if (T == Enumerated) {
        fields.parser.state = .Int64;
        switch ((try fields.next()) orelse @panic("aaa")) {
            .Int64 => |int32| return int32,
            else => return error.UnexpectedField,
        }
    }

    if (T == Flag) return true;

    if (T == std.math.big.int.Managed) {
        fields.parser.state = .BigInt;
        switch ((try fields.next()) orelse @panic("aaa")) {
            .BigInt => |big_int| return big_int,
            else => return error.UnexpectedField,
        }
    }

    switch (@typeInfo(T)) {
        .Bool => {
            fields.parser.state = .Bool;
            switch ((try fields.next()) orelse @panic("aaa")) {
                .Bool => |b| return b,
                else => return error.UnexpectedField,
            }
        },
        .Int => {
            @panic("not implemented yet!");
        },
        .Struct => |struct_info| {
            var r: T = undefined;
            var fields_seen = [_]bool{false} ** struct_info.fields.len;

            inline for (struct_info.fields) |struct_field, i| {
                if (internal_fields.i == 0 and struct_field.field_type == RawContent) {
                    fields_seen[i] = true;
                } else {
                    @field(r, struct_field.name) = try parse(allocator, struct_field.field_type, &internal_fields, options);
                    fields_seen[i] = true;
                }
            }

            return r;

            // while (true) {
            //     if (fields.parser.) {}
            //     switch ((try fields.next()) orelse @panic("aaaa")) {
            //         .TagAndLength => |tag_and_length| {
            //             var found = false;
            //             inline for (struct_info.fields) |struct_field, i| {
            //                 if (struct_field.type == TagAndLength) {
            //                     if (!fields_seen[i]) {
            //                         @field(r, struct_field.name) = tag_and_length;

            //                         fields_seen[i] = true;
            //                         found = true;
            //                         break;
            //                     }
            //                 }
            //             }
            //             if (!found) {
            //                 return error.UnknownField;
            //             }
            //         },
            //         else => @panic("not implemented yet!"),
            //     }
            // }

            // @panic("not implemented yet!");
        },
        .Pointer => {
            // .Slice => {
            @panic("not implemented yet!");
            // },
        },
        // String?
        else => @panic("not supported!"),
    }
}

pub fn ParseError(comptime T: type) type {
    return ParseInternalError(T) || error{UnexpectedEndOfAsn1} || FieldStream.Error;
}

pub fn parse(allocator: std.mem.Allocator, comptime T: type, fields: *FieldStream, options: ParseOptions) ParseError(T)!T {
    const field = (try fields.next()) orelse return error.UnexpectedEndOfAsn1;
    std.debug.print("--\n{d}\n", .{fields.buf});
    std.debug.print("--\n{d}\n", .{fields.i});
    std.debug.print("--\n{}\n", .{field});
    const r = try parseInternal(allocator, T, field, fields, options);
    // TODO: parserFree
    // TODO: trailing data
    return r;

    // switch (@typeInfo(T)) {

    //     // .Int => |intInfo| {
    //     //     if (intInfo.bits < 32) @panic("aaaaaa");

    //     // },
    //     .Struct => {
    //         var r: T = undefined;
    //         // var fields_seen = [_]bool{false} ** structInfo.fields.len;

    //         switch ((try fields.next()) orelse @panic("aa")) {
    //             .TagAndLength => |tagAndLengthField| {
    //                 r = tagAndLengthField;
    //             },
    //             // .IntBase128 => |intBase128Field| {

    //             // }
    //             else => @panic("aaa"),
    //         }

    //         // inline for (structInfo.fields) |struct_field, i| {
    //         //     if (!fields_seen[i]) {
    //         //         if (struct_field.default_value) |default| {
    //         //             if (!struct_field.is_comptime) {
    //         //                 @field(r, struct_field.name) = default;
    //         //             }
    //         //         } else {
    //         //             return error.MissingField;
    //         //         }
    //         //     }
    //         // }

    //         return r;
    //     },
    //     else => @panic("aaaaa"),
    // }
}

// test "parse should work as expected" {
//     const ParseTest = struct {
//         pub fn parseTest(in: []const u8, comptime T: type, out: T) !void {
//             const parsed = x: {
//                 var stream = FieldStream.init(in);
//                 const res = try parse(T, &stream, .{});
//                 break :x res;
//             };

//             try std.testing.expectEqual(out, parsed);
//         }
//     };

//     try ParseTest.parseTest(&.{ 0x02, 0x01, 0x42 }, i32, 0x42);
// }

// test "parse tag and length" {
//     const TagAndLengthTest = struct {
//         in: []const u8,
//         ok: bool,
//         out: TagAndLength,
//     };

//     const tagAndLengthData = &[_]TagAndLengthTest{
//         .{ .in = &.{ 0x80, 0x01 }, .ok = true, .out = .{
//             .class = 2,
//             .tag = 0,
//             .length = 1,
//             .is_compound = false,
//         } },
//         .{ .in = &.{ 0xa0, 0x01 }, .ok = true, .out = .{
//             .class = 2,
//             .tag = 0,
//             .length = 1,
//             .is_compound = true,
//         } },
//         .{ .in = &.{ 0x02, 0x00 }, .ok = true, .out = .{
//             .class = 0,
//             .tag = 2,
//             .length = 0,
//             .is_compound = false,
//         } },
//         .{ .in = &.{ 0xfe, 0x00 }, .ok = true, .out = .{
//             .class = 3,
//             .tag = 30,
//             .length = 0,
//             .is_compound = true,
//         } },
//         .{ .in = &.{ 0x1f, 0x1f, 0x00 }, .ok = true, .out = .{
//             .class = 0,
//             .tag = 31,
//             .length = 0,
//             .is_compound = false,
//         } },
//         .{ .in = &.{ 0x1f, 0x81, 0x00, 0x00 }, .ok = true, .out = .{
//             .class = 0,
//             .tag = 128,
//             .length = 0,
//             .is_compound = false,
//         } },
//         .{ .in = &.{ 0x1f, 0x81, 0x80, 0x01, 0x00 }, .ok = true, .out = .{
//             .class = 0,
//             .tag = 0x4001,
//             .length = 0,
//             .is_compound = false,
//         } },
//         .{ .in = &.{ 0x00, 0x81, 0x80 }, .ok = true, .out = .{
//             .class = 0,
//             .tag = 0,
//             .length = 128,
//             .is_compound = false,
//         } },
//         .{ .in = &.{ 0x00, 0x82, 0x01, 0x00 }, .ok = true, .out = .{
//             .class = 0,
//             .tag = 0,
//             .length = 256,
//             .is_compound = false,
//         } },
//         .{ .in = &.{ 0x00, 0x83, 0x01, 0x00 }, .ok = false, .out = .{
//             .class = 0,
//             .tag = 0,
//             .length = 0,
//             .is_compound = false,
//         } },
//         .{ .in = &.{ 0x1f, 0x85 }, .ok = false, .out = .{
//             .class = 0,
//             .tag = 0,
//             .length = 0,
//             .is_compound = false,
//         } },
//         .{ .in = &.{ 0x30, 0x80 }, .ok = false, .out = .{
//             .class = 0,
//             .tag = 0,
//             .length = 0,
//             .is_compound = false,
//         } },
//         .{ .in = &.{ 0xa0, 0x82, 0x00, 0xff }, .ok = false, .out = .{
//             .class = 0,
//             .tag = 0,
//             .length = 0,
//             .is_compound = false,
//         } },
//         .{ .in = &.{ 0xa0, 0x84, 0x7f, 0xff, 0xff, 0xff }, .ok = true, .out = .{
//             .class = 2,
//             .tag = 0,
//             .length = 0x7fffffff,
//             .is_compound = true,
//         } },
//         .{ .in = &.{ 0xa0, 0x84, 0x80, 0x00, 0x00, 0x00 }, .ok = false, .out = .{
//             .class = 0,
//             .tag = 0,
//             .length = 0,
//             .is_compound = false,
//         } },
//         .{ .in = &.{ 0xa0, 0x81, 0x7f }, .ok = false, .out = .{
//             .class = 0,
//             .tag = 0,
//             .length = 0,
//             .is_compound = false,
//         } },
//         .{ .in = &.{ 0x1f, 0x88, 0x80, 0x80, 0x80, 0x00, 0x00 }, .ok = false, .out = .{
//             .class = 0,
//             .tag = 0,
//             .length = 0,
//             .is_compound = false,
//         } },
//         .{ .in = &.{ 0x1f, 0x87, 0xff, 0xff, 0xff, 0x7f, 0x00 }, .ok = true, .out = .{
//             .class = 0,
//             .tag = std.math.maxInt(i32),
//             .length = 0,
//             .is_compound = false,
//         } },
//         .{ .in = &.{ 0x1f, 0x1e, 0xff, 0x00 }, .ok = false, .out = .{
//             .class = 0,
//             .tag = 0,
//             .length = 0,
//             .is_compound = false,
//         } },
//     };

//     for (tagAndLengthData) |t| {
//         const parsed = x: {
//             var stream = FieldStream.init(t.in);
//             const res = parse(TagAndLength, &stream, .{}) catch {
//                 try std.testing.expect(!t.ok);
//                 continue;
//             };
//             break :x res;
//         };

//         try std.testing.expectEqual(t.out, parsed);
//     }
// }

comptime {
    std.testing.refAllDecls(@This());
}
