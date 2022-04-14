const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const U256 = [32]u8;

pub fn double_sha256(input: []const u8, output: *U256) void {
    Sha256.hash(input, output, .{});
    Sha256.hash(output, output, .{});
}
