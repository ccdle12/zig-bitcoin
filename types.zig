const std = @import("std");
const testing = std.testing;

/// VarInt (variable integer) is a type that is used in transaction data to identify
/// the following number of serialized fields or the length of the following serialized
/// fields.
///
/// The maximum size a varint can hold is the max of a u64. The VarInt is encoded
/// in such a way that we don't need to use the full 8 bytes for a u64 if the
/// VarInt integer can be expressed in less than 8 bytes. Below is an example
/// of the VarInts at different sizes:
///
/// Size:             Example:            Prefix:
/// <= OxFC             12                  None
/// <= 0xFFFF         fd1234                Add prefix fd, and the next 2 bytes is the VarInt little endian
/// <= 0xFFFFFFFF     fd12345678            Add prefix fe, and the next 4 bytes is the VarInt little endian
/// <= MAX            ff1234567890acbdef    Add prefix ff, and the next 8 bytes is the VarInt little endian
pub const VarInt = struct {
    pub fn size(varint: u64) usize {
        return switch (varint) {
            0...0xFC => 1,
            0xFD...0xFFFF => 3,
            0x10000...0xFFFFFFFF => 5,
            else => 9,
        };
    }
};

test "VarInt size" {
    try testing.expectEqual(VarInt.size(1), 1);
    try testing.expectEqual(VarInt.size(0xFD), 3);
    try testing.expectEqual(VarInt.size(0xFFFF), 3);
    try testing.expectEqual(VarInt.size(0xFFFF + 1), 5);
    try testing.expectEqual(VarInt.size(0x10000), 5);
    try testing.expectEqual(VarInt.size(0xFFFFFFFF), 5);
    try testing.expectEqual(VarInt.size(0xFFFFFFFFFFFFFFFF), 9);
}
