const std = @import("std");

const io = std.io;
const testing = std.testing;

const ArrayList = std.ArrayList;

/// VarInt (variable integer) is a type that is used in transaction data to identify
/// the following number of serialized fields or the length of the following serialized
/// fields.
///
/// The maximum size a varint can hold is the max of a u64. The VarInt is encoded
/// in such a way that we don't need to use the full 8 bytes for a u64 if the
/// VarInt can be expressed in less than 8 bytes. 
///
/// Below is an example of the VarInts at different sizes:
///
/// Size:             Example:            Prefix:
/// <= OxFC             12                  None
/// <= 0xFFFF         fd1234                Add prefix fd, and the next 2 bytes is the VarInt little endian
/// <= 0xFFFFFFFF     fd12345678            Add prefix fe, and the next 4 bytes is the VarInt little endian
/// <= MAX            ff1234567890acbdef    Add prefix ff, and the next 8 bytes is the VarInt little endian
pub const VarInt = struct {
    inner: u64,

    const Error = error{
        InvalidBytePrefix,
    };

    pub fn init(varint: u64) VarInt {
        return .{
            .inner = varint,
        };
    }
    // pub fn size(varint: u64) usize {
    pub fn size(self: @This()) usize {
        return switch (self.inner) {
            0...0xFC => 1,
            0xFD...0xFFFF => 3,
            0x10000...0xFFFFFFFF => 5,
            else => 9,
        };
    }

    pub fn write(self: @This(), writer: anytype) !void {
        return switch (self.inner) {
            0...0xFC => writer.writeIntLittle(u8, @intCast(u8, self.inner)),
            0xFD...0xFFFF => {
                try writer.writeIntLittle(u8, 0xFD);
                try writer.writeIntLittle(u16, @intCast(u16, self.inner));
            },
            0x10000...0xFFFFFFFF => {
                try writer.writeIntLittle(u8, 0xFE);
                try writer.writeIntLittle(u32, @intCast(u32, self.inner));
            },
            else => {
                try writer.writeIntLittle(u8, 0xFF);
                try writer.writeIntLittle(u64, self.inner);
            },
        };
    }

    pub fn read(reader: anytype) !VarInt {
        const prefix = try reader.readIntNative(u8);

        if (prefix <= 0xFC) {
            return VarInt{ .inner = prefix };
        }

        return switch (prefix) {
            0xFD => VarInt{ .inner = try reader.readIntNative(u16) },
            0xFE => VarInt{ .inner = try reader.readIntNative(u32) },
            0xFF => VarInt{ .inner = try reader.readIntNative(u64) },
            else => error.InvalidBytePrefix,
        };
    }
};

test "VarInt size" {
    try testing.expectEqual(VarInt.init(1).size(), 1);
    try testing.expectEqual(VarInt.init(0xFD).size(), 3);
    try testing.expectEqual(VarInt.init(0xFFFF).size(), 3);
    try testing.expectEqual(VarInt.init(0xFFFF + 1).size(), 5);
    try testing.expectEqual(VarInt.init(0x10000).size(), 5);
    try testing.expectEqual(VarInt.init(0xFFFFFFFF).size(), 5);
    try testing.expectEqual(VarInt.init(0xFFFFFFFFFFFFFFFF).size(), 9);
}

/// Internal helper function to repeat the VarInt serialization tests.
fn serialize_test(
    serialized: *ArrayList(u8),
    input: u64,
    expected: []const u8,
) !void {
    try VarInt.init(input).write(serialized.writer());
    try testing.expectEqualSlices(u8, serialized.items, expected);
    serialized.clearAndFree();
}

test "VarInt serialize" {
    var serialized = ArrayList(u8).init(testing.allocator);
    defer serialized.deinit();

    try serialize_test(&serialized, 9, &[_]u8{0x09});
    try serialize_test(&serialized, 0xFC, &[_]u8{0xFC});
    try serialize_test(&serialized, 0xFD, &[_]u8{ 0xFD, 0xFD, 0x00 });
    try serialize_test(&serialized, 0xFFFF, &[_]u8{ 0xFD, 0xFF, 0xFF });
    try serialize_test(&serialized, 0x10000, &[_]u8{ 0xFE, 0x00, 0x00, 0x01, 0x00 });
    try serialize_test(&serialized, 0xFFFFFFFF, &[_]u8{ 0xFE, 0xFF, 0xFF, 0xFF, 0xFF });
    try serialize_test(&serialized, 0xFFFFFFFFFFFFFFFF, &[_]u8{0xFF} ** 9);
}

/// Internal helper function to repeat the VarInt serialization tests.
fn deserialize_test(
    input: []const u8,
    expected: u64,
) !void {
    const varint = try VarInt.read(
        io.fixedBufferStream(input).reader(),
    );
    try testing.expectEqual(varint.inner, expected);
}

test "VarInt deserialize" {
    try deserialize_test(&[_]u8{0x09}, 9);
    try deserialize_test(&[_]u8{0xFC}, 252);
    try deserialize_test(&[_]u8{ 0xFD, 0xFD, 0x00 }, 253);
    try deserialize_test(&[_]u8{ 0xFD, 0xFF, 0xFF }, 65535);
    try deserialize_test(&[_]u8{ 0xFE, 0x00, 0x00, 0x01, 0x00 }, 65536);
    try deserialize_test(&[_]u8{ 0xFE, 0xFF, 0xFF, 0xFF, 0xFF }, 4294967295);
    try deserialize_test(&[_]u8{0xFF} ** 9, 18446744073709551615);

    // TODO: Test the error.
}
