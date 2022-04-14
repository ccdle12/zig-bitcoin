const std = @import("std");
const hash = @import("./hash.zig");
const transaction = @import("./transaction.zig");

const mem = std.mem;
const testing = std.testing;

const ArrayList = std.ArrayList;
const Transaction = transaction.Transaction;
const U256 = hash.U256;

// BlockHeader contains all information of Block minus all the actual transactions.
pub const BlockHeader = struct {
    // The protocol version used.
    version: i32,

    // A reference to the hash of the previous block in the chain.
    prev_blockhash: U256,

    // The root hash of the all the transactions in the Merkle Tree.
    merkle_root: U256,

    time: u32,

    // The target for the POW, the blockhash must be under this target.
    bits: u32,

    // Nonce is used to find a blockhash below the target (bits).
    nonce: u32,
};

// Block is the actual Block used in the network that contains the BlockHeader
// and the actual transactions.
pub const Block = struct {
    header: BlockHeader,
    tx_data: ArrayList(Transaction),

    fn init(gpa: *mem.Allocator, header: BlockHeader) Block {
        return .{
            .header = header,
            .tx_data = std.ArrayList(Transaction).init(gpa),
        };
    }

    fn deinit(self: @This()) void {
        self.tx_data.deinit();
    }
};
