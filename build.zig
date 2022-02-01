const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const lib = b.addStaticLibrary("zig-rsa", "src/main.zig");
    lib.setBuildMode(mode);
    lib.install();

    const main_tests = b.addTest("src/asn1.zig");
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);

    const debug_bin = b.addExecutable("debug", "src/examples/x509.zig");
    debug_bin.addPackage(.{
        .name = "zig-rsa",
        .path = .{ .path = "src/main.zig" },
    });
    debug_bin.setBuildMode(mode);
    debug_bin.install();

    const prepare_out = b.addSystemCommand(&[_][]const u8{ "mkdir", "-p", "zig-out/bin" });

    const symlink = b.addSystemCommand(&[_][]const u8{ "ln", "-s", "-f" });
    symlink.addArtifactArg(debug_bin);
    symlink.addArg("zig-out/bin/debug");

    const debug_step = b.step("debug", "Debug the application");
    debug_step.dependOn(&lib.step);
    debug_step.dependOn(&debug_bin.step);
    debug_step.dependOn(&prepare_out.step);
    debug_step.dependOn(&symlink.step);

    // const debug_tests = b.addTestExe("debug", "src/main.zig");
    // debug_tests.setBuildMode(mode);
    // debug_tests.install();

    // const debug_step = b.step("debug", "Build a test binary");
    // debug_step.dependOn(&debug_tests.step);
    // debug_step.dependOn(&prepare_out.step);
    // debug_step.dependOn(&symlink.step);
}
