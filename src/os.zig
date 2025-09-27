//! OS-level functionality.
//! Designed to be slightly higher level than sys.zig
const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("pwd.h");
    @cInclude("limits.h");
    @cInclude("errno.h");
});

/// Opaque type representing the user ID.
pub const Uid = struct {
    const Self = @This();

    _underlying: std.c.uid_t,

    pub fn queryEffective() Self {
        // TODO(markovejnovic): Unfortunately, geteuid is not available in Zig's stdlib at the
        //                      moment, so we need to use @cImport above.
        return .{ ._underlying = c.geteuid() };
    }

    pub fn queryReal() Self {
        // TODO(markovejnovic): Unfortunately, getuid is not available in Zig's stdlib at the
        //                      moment, so we need to use @cImport above.
        return .{ ._underlying = c.getuid() };
    }

    /// Falls back to queryEffective.
    pub fn queryCurrent() Self {
        return queryEffective();
    }
};

/// Utilities for fetching and interacting with the current system home directory.
pub const HomeDir = union(enum) {
    pub const QueryOpts = struct {
        user: ?[]const u8 = null,
    };

    const Self = @This();

    _system_managed: struct {
        value: []const u8,
    },

    _manually_managed: SlicedBuffer,

    pub fn slice(self: Self) []const u8 {
        return switch (self) {
            ._system_managed => |s| s.value,
            ._manually_managed => |m| m.slice,
        };
    }

    pub fn deinit(self: Self) void {
        switch (self) {
            ._system_managed => {
                // System managed the home directory for us, so we don't need to free it.
            },
            ._manually_managed => |*m| {
                m.deinit();
            },
        }
    }

    /// Deduces the current user's home directory.
    ///
    /// Has multiple strategies depending on the platform and environment. Mostly compliant with
    /// the POSIX standard for POSIX systems.
    ///
    /// No compliance claims are made for Windows.
    pub fn query(allocator: std.mem.Allocator, opts: QueryOpts) !Self {
        if (opts.user != null) {
            // There is actually a reasonable desire to be able to query other users' home
            // directories. However, we don't have a need to do that at this moment. See
            // doi:10.1109/IEEESTD.2018.8277153 2.6.1 for further details.
            @panic("Not implemented");
        }

        return if (bun.Environment.isWindows)
            queryWin(allocator, opts)
        else
            queryPosix(allocator, opts);
    }

    /// Deduces the current user's home directory on POSIX systems.
    ///
    /// Whichever of the following returns a value is returned.
    /// - Per doi:10.1109/IEEESTD.2018.8277153, the `$HOME` variable.
    /// - The `getpwuid_r` function.
    fn queryPosix(allocator: std.mem.Allocator, opts: QueryOpts) !Self {
        if (bun.Environment.isWindows) {
            @compileError("You cannot call queryPosix on Windows");
        }

        if (opts.user != null) {
            // There is actually a reasonable desire to be able to query other users' home
            // directories. However, we don't have a need to do that. See
            // doi:10.1109/IEEESTD.2018.8277153 2.6.1 for further details.
            @panic("Not implemented");
        }

        if (bun.EnvVar.home.get()) |h| {
            return .{ ._system_managed = .{ .value = h } };
        }

        const max_attempts = 8; // The maximum total number of attempts we will have at reading
        // getpwuid_r before giving up. There are a few cases which benefit
        // from re-attempting a read.
        // TODO(markovejnovic): std.c does not expose c._SC_GETPW_R_SIZE_MAX at the moment, so we
        //                      need to use @cImport above.
        const initial_buf_size: usize = @intCast(std.c.sysconf(c._SC_GETPW_R_SIZE_MAX));
        const buf_size_gain = 4;

        var buffer_size: usize = initial_buf_size;
        var managed_dir: Self = .{ ._manually_managed = .{
            .buf = try allocator.alloc(u8, buffer_size),
            .slice = undefined,
            .allocator = allocator,
        } };
        var m = &managed_dir._manually_managed;
        errdefer m.allocator.free(m.buf);

        for (0..max_attempts) |_| {
            var passwd: c.struct_passwd = undefined;
            var result: *c.struct_passwd = undefined;

            // On success, getpwnam_r() and getpwuid_r() return zero, and set *result to pwd.
            // TODO(markovejnovic): Unfortunately, at the time of writing, Zig's std.c.getpwuid_r
            //                      aliases to openBSD's getpwuid_r, which doesn't wrok.
            //                      Consequently, we need to use @cImport above.
            const rc = c.getpwuid_r(
                Uid.queryCurrent()._underlying,
                &passwd,
                m.buf.ptr,
                m.buf.len,
                @ptrCast(&result),
            );
            if (rc == 0) {
                // Great, we found a password entry, with a home directory. Let's patch up
                // ManagedHomeDir and ship it.
                if (result.pw_dir == null) {
                    return error.FailedToFindHomeDir;
                }

                const dir = result.pw_dir;

                m.slice = dir[0..std.mem.len(dir)];
                return managed_dir;
            }

            switch (std.posix.errno(rc)) {
                .INTR => {
                    // We got hit by a signal, let's just try again.
                    continue;
                },
                .IO => {
                    // I/O error.
                    //
                    // Perhaps trying again later will work?
                    return error.TryAgainLater;
                },
                .MFILE => {
                    // The maximum number (OPEN_MAX) of files was open already in the calling
                    // process.
                    //
                    // Perhaps trying again later will work?
                    return error.TryAgainLater;
                },
                .NFILE => {
                    // The maximum number of files was open already in the system.
                    //
                    // Perhaps trying again later will work?
                    return error.TryAgainLater;
                },
                .NOMEM, .RANGE => {
                    // ENOMEM -- Insufficient memory to allocate passwd structure.
                    // ERANGE -- Insufficient buffer space supplied.
                    buffer_size *= buf_size_gain;
                    m.buf = try m.allocator.realloc(m.buf, buffer_size);
                    continue;
                },
                else => {
                    // 0 or ENOENT or ESRCH or EBADF or EPERM or ... The given name or uid was not
                    // found -- there's really no point in trying again.
                    break;
                },
            }
        }

        return error.FailedToFindHomeDir;
    }

    /// Deduces the current user's home directory on POSIX systems.
    ///
    /// Whichever of the following returns a value is returned.
    /// - Per doi:10.1109/IEEESTD.2018.8277153, the %UserProfile% environment variable.
    fn queryWin(allocator: std.mem.Allocator, opts: QueryOpts) !Self {
        if (!bun.Environment.isWindows) {
            @compileError("You cannot call queryWin on POSIX");
        }

        if (opts.user != null) {
            // There is actually a reasonable desire to be able to query other users' home
            // directories. However, we don't have a need to do that. See
            // doi:10.1109/IEEESTD.2018.8277153 2.6.1 for further details.
            @panic("Not implemented");
        }

        _ = allocator;

        if (bun.EnvVar.home.get()) |h| {
            return .{ ._system_managed = .{
                .value = h,
            } };
        }

        return error.FailedToFindHomeDir;
    }
};

const bun = @import("bun");
const std = @import("std");
const SlicedBuffer = bun.string.immutable.SlicedBuffer;
