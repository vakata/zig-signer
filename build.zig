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

    const picker = addPicker(b, target, optimize);

    const xml = b.dependency("xml", .{
        .target = target,
        .optimize = std.builtin.OptimizeMode.ReleaseFast,
    });
    exe.root_module.addImport("xml", xml.module("xml"));

    const httpz = b.dependency("httpz", .{
        .target = target,
        .optimize = std.builtin.OptimizeMode.ReleaseFast,
    });
    exe.root_module.addImport("httpz", httpz.module("httpz"));

    b.installArtifact(exe);
    b.installArtifact(picker);

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

fn addPicker(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step.Compile {
    const picker = b.addExecutable(.{
        .name = "signer-picker",
        .root_module = b.createModule(.{
            .root_source_file = null,
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    const picker_c_flags: []const []const u8 = switch (optimize) {
        .Debug => &.{"-DCMAKE_DEBUG"},
        .ReleaseSafe => &.{"-DCMAKE_RELEASEWITHASSERT"},
        .ReleaseFast, .ReleaseSmall => &.{"-DCMAKE_RELEASE"},
    };
    picker.root_module.addCSourceFile(.{
        .file = b.path("src/gui/picker.c"),
        .flags = picker_c_flags,
    });

    inline for (.{ "sewer", "osbs", "core", "geom2d", "draw2d", "gui", "osapp" }) |include|
        picker.root_module.addIncludePath(b.path("vendor/nappgui/inc/" ++ include));

    const lib_dir = nappguiLibraryDir(b, target.result, optimize);
    const extension = if (target.result.os.tag == .windows) ".lib" else ".a";
    const prefix = if (target.result.os.tag == .windows) "" else "lib";

    // Static-library order follows the dependency chain from osapp to sewer.
    inline for (.{ "osapp", "gui", "osgui", "draw2d", "geom2d", "core", "osbs", "sewer" }) |lib| {
        const filename = b.fmt("{s}{s}{s}", .{ prefix, lib, extension });
        picker.root_module.addObjectFile(b.path(b.pathJoin(&.{ "vendor/nappgui/lib", lib_dir, filename })));
    }

    switch (target.result.os.tag) {
        .linux => {
            picker.root_module.link_libcpp = true;
            picker.root_module.linkSystemLibrary("gtk-3", .{});
            picker.root_module.linkSystemLibrary("gdk-3", .{});
            picker.root_module.linkSystemLibrary("pangocairo-1.0", .{});
            picker.root_module.linkSystemLibrary("pango-1.0", .{});
            picker.root_module.linkSystemLibrary("harfbuzz", .{});
            picker.root_module.linkSystemLibrary("atk-1.0", .{});
            picker.root_module.linkSystemLibrary("cairo-gobject", .{});
            picker.root_module.linkSystemLibrary("cairo", .{});
            picker.root_module.linkSystemLibrary("gdk_pixbuf-2.0", .{});
            picker.root_module.linkSystemLibrary("gio-2.0", .{});
            picker.root_module.linkSystemLibrary("gobject-2.0", .{});
            picker.root_module.linkSystemLibrary("glib-2.0", .{});
            picker.root_module.linkSystemLibrary("pthread", .{});
            picker.root_module.linkSystemLibrary("dl", .{});
            picker.root_module.linkSystemLibrary("m", .{});
        },
        .macos => {
            picker.root_module.linkFramework("Cocoa", .{});
            picker.root_module.linkFramework("UniformTypeIdentifiers", .{});
        },
        .windows => {
            picker.subsystem = .windows;
        },
        else => @panic("NAppGUI supports only Linux, macOS and Windows"),
    }

    return picker;
}

fn nappguiLibraryDir(b: *std.Build, target: std.Target, optimize: std.builtin.OptimizeMode) []const u8 {
    const config = switch (optimize) {
        .Debug => "Debug",
        .ReleaseSafe => "ReleaseWithAssert",
        .ReleaseFast, .ReleaseSmall => "Release",
    };
    const toolset = switch (target.os.tag) {
        .linux => switch (target.cpu.arch) {
            .x86_64 => "gcc11_gtk3_x64",
            .aarch64 => "gcc10_gtk3_arm64",
            else => @panic("NAppGUI's bundled Linux libraries support x86_64 and aarch64"),
        },
        .macos => switch (target.cpu.arch) {
            .x86_64 => "sdk12_0_x64",
            .aarch64 => "sdk12_0_arm",
            else => @panic("NAppGUI's bundled macOS libraries support x86_64 and aarch64"),
        },
        .windows => switch (target.cpu.arch) {
            .x86_64 => "v143_x64",
            else => @panic("NAppGUI's bundled Windows libraries support x86_64"),
        },
        else => @panic("NAppGUI supports only Linux, macOS and Windows"),
    };
    return b.pathJoin(&.{ toolset, config });
}
