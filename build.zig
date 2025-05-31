const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addIncludePath(.{ .cwd_relative = "src" });

    const exe = b.addExecutable(.{
        .name = "signer",
        .root_module = exe_mod,
    });

    const p11 = b.dependency("p11", .{}).path("common");
    exe.root_module.addIncludePath(p11);
    exe.root_module.addIncludePath(b.path("include"));

    const zig_webui = b.dependency("zig_webui", .{
        .target = target,
        .optimize = optimize,
        .enable_tls = false, // whether enable tls support
        .is_static = true, // whether static link
    });
    exe.root_module.addImport("webui", zig_webui.module("webui"));

    const xml = b.dependency("xml", .{
        .target = target,
        .optimize = optimize,
    });
    exe.root_module.addImport("xml", xml.module("xml"));

    const httpz = b.dependency("httpz", .{
        .target = target,
        .optimize = optimize,
    });
    exe.root_module.addImport("httpz", httpz.module("httpz"));

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_unit_tests = b.addTest(.{
        .root_module = exe_mod,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);
}
