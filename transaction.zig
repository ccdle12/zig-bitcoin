// TODO:
// How do identify if a transaction is Segwit and a segwit type, e.g. P2WKH, P2WSH?
const std = @import("std");
const hash = @import("./hash.zig");

const fmt = std.fmt;
const io = std.io;
const mem = std.mem;
const testing = std.testing;

const ArrayList = std.ArrayList;
const double_sha256 = hash.double_sha256;
const U256 = hash.U256;

pub const Transaction = struct {
    // The protocol version (2 is the current default).
    version: i32 = 2,

    // Transaction inputs to fund the transaction.
    inputs: ArrayList(TxIn),

    // Transaction outputs used to send coins to receivers.
    outputs: ArrayList(TxOut),

    // The time in blocks where the transaction will become valid. 0 indicates
    // it's valid immediately.
    lock_time: u32,

    gpa: *mem.Allocator,

    const Error = error{
        InvalidSegwitFlag,
    };

    fn init(gpa: *mem.Allocator, version: i32, lock_time: u32) Transaction {
        return .{
            .version = version,
            .inputs = std.ArrayList(TxIn).init(gpa),
            .outputs = std.ArrayList(TxOut).init(gpa),
            .lock_time = lock_time,
            .gpa = gpa,
        };
    }

    fn read(gpa: *mem.Allocator, reader: anytype) !Transaction {
        const version = try reader.readIntNative(i32);

        const inputs_len = blk: {
            var len = try reader.readIntNative(u8);
            if (len == 0x00) {
                // This is a segwit transaction because 0x00 is set as the marker.
                const flag = try reader.readIntNative(u8);
                if (flag != 0x01) return Transaction.Error.InvalidSegwitFlag;

                // The next byte should be the length of inputs for segwit txs.
                len = try reader.readIntNative(u8);
            }

            break :blk len;
        };

        var inputs = blk: {
            var in = std.ArrayList(TxIn).init(gpa);

            var i: usize = 0;
            while (i < inputs_len) : (i += 1)
                try in.append(try TxIn.read(gpa, reader));

            break :blk in;
        };

        // TODO: The witness comes later in the tx, need to assign them to the correct inputs later?
        const outputs_len = try reader.readIntNative(u8);
        const outputs = blk: {
            var out = std.ArrayList(TxOut).init(gpa);

            var i: usize = 0;
            while (i < outputs_len) : (i += 1)
                try out.append(try TxOut.read(gpa, reader));

            break :blk out;
        };

        // TODO:
        // - Assign to inputs, but how do we know if we have multiple???
        // - input[0].witness = witness;
        const witness = try Witness.read(gpa, reader);
        inputs.items[0].witness = witness;

        const lock_time = try reader.readIntNative(u32);

        return Transaction{
            .version = version,
            .inputs = inputs,
            .outputs = outputs,
            .lock_time = lock_time,
            .gpa = gpa,
        };
    }

    fn write(self: @This(), writer: anytype) !void {
        try self.internal_write(writer, true);
    }

    // The internal_write function has an include_witness flag that is mainly
    // used for serializing and hashing a txid. This gives the caller the option
    // to include the witness data in the transaction hash or omitting it (Segwit).
    fn internal_write(self: @This(), writer: anytype, include_witness: bool) !void {
        try writer.writeIntLittle(i32, self.version);

        var is_segwit = false;
        for (self.inputs.items) |input| {
            if (input.witness) |_| {
                is_segwit = true;
                break;
            }
        }

        if (is_segwit and include_witness) {
            try writer.writeIntLittle(u8, 0x00);
            try writer.writeIntLittle(u8, 0x01);
        }

        try writer.writeIntLittle(u8, @intCast(u8, self.inputs.items.len));
        for (self.inputs.items) |input| try input.write(writer);

        try writer.writeIntLittle(u8, @intCast(u8, self.outputs.items.len));
        for (self.outputs.items) |output| try output.write(writer);

        if (is_segwit and include_witness) {
            for (self.inputs.items) |input|
                try input.witness.?.write(writer);
        }

        try writer.writeIntLittle(u32, self.lock_time);
    }

    fn wtxid(self: @This(), output: *U256) !void {
        try self.internal_hash(output, true);
    }

    fn txid(self: @This(), output: *U256) !void {
        try self.internal_hash(output, false);
    }

    fn internal_hash(self: @This(), output: *U256, include_witness: bool) !void {
        var serialized = ArrayList(u8).init(self.gpa);
        defer serialized.deinit();

        try self.internal_write(serialized.writer(), include_witness);

        double_sha256(serialized.items, output);
        mem.reverse(u8, output);
    }

    fn deinit(self: @This()) void {
        for (self.inputs.items) |input| input.deinit();
        self.inputs.deinit();

        for (self.outputs.items) |output| output.deinit();
        self.outputs.deinit();
    }
};

// A reference to a Transaction Output used in Transaction Inputs.
pub const OutPoint = struct {
    // TODO CCDLE12: This should be reversed
    // The tranaction id that's being referenced.
    txid: U256,

    // The index position of the referenced output in the transactions output.
    vout: u32,

    fn read(reader: anytype) !OutPoint {
        // TODO: Make sure I know exactly why the txid is littleendian/bigendian
        // txid needs to be reversed.
        var txid = try reader.readBytesNoEof(32); // TODO: Use a name variable for the size
        mem.reverse(u8, &txid);

        return OutPoint{
            .txid = txid,
            .vout = try reader.readIntNative(u32),
        };
    }

    fn write(self: @This(), writer: anytype) !void {
        var txid = self.txid;
        mem.reverse(u8, &txid);

        try writer.writeAll(&txid);
        try writer.writeIntLittle(u32, self.vout);
    }
};

// Transaction Input used to reference coins to consume in a Tranasction.
pub const TxIn = struct {
    // The previous transaction output that is going to be used.
    previous_output: OutPoint,

    // The opcodes as bytes used in the unlocking script to access the previous_output.
    script_sig: []const u8,

    // Used to prioritize conflicting transactions. By default will be set to
    // 0xFFFFFFFF to not use this feature.
    sequence: u32 = 0xFFFFFFFF,

    // TODO: Witness data???
    witness: ?Witness,

    gpa: *mem.Allocator,

    fn read(gpa: *mem.Allocator, reader: anytype) !TxIn {
        const previous_output = try OutPoint.read(reader);

        const script_sig = blk: {
            const len = try reader.readByte();
            const sig = try gpa.alloc(u8, len);
            errdefer gpa.free(sig);
            _ = try reader.read(sig);

            break :blk sig;
        };

        const sequence = try reader.readIntNative(u32);

        return TxIn{
            .previous_output = previous_output,
            .script_sig = script_sig,
            .sequence = sequence,
            .witness = null,
            .gpa = gpa,
        };
    }

    fn write(self: @This(), writer: anytype) !void {
        try self.previous_output.write(writer);
        try writer.writeAll(self.script_sig);
        if (self.script_sig.len == 0) {
            try writer.writeIntLittle(u8, 0x00);
        }
        try writer.writeIntLittle(u32, self.sequence);
    }

    pub fn deinit(self: @This()) void {
        self.gpa.free(self.script_sig);
        if (self.witness) |w| w.deinit();
    }
};

// Transaction Ouput contains a numeric value and a challenge for the receiver
// to prove ownership. The receiver would consume the TxOut as a TxIn in a
// subsequent Transaction.
pub const TxOut = struct {
    // The value of the transaction output in satoshis.
    value: u64,

    // The locking script on the transaction output.
    script_pubkey: []const u8,

    gpa: *mem.Allocator,

    // TODO: Not sure if this is correct,need to test these values
    fn read(gpa: *mem.Allocator, reader: anytype) !TxOut {
        const value = try reader.readIntNative(u64);

        const script_pubkey_len = try reader.readByte();
        const script_pubkey = try gpa.alloc(u8, script_pubkey_len);
        _ = try reader.read(script_pubkey);

        return TxOut{
            .value = value,
            .script_pubkey = script_pubkey,
            .gpa = gpa,
        };
    }

    fn write(self: @This(), writer: anytype) !void {
        try writer.writeIntLittle(u64, self.value);
        try writer.writeIntLittle(u8, @intCast(u8, self.script_pubkey.len));
        try writer.writeAll(self.script_pubkey);
    }

    pub fn deinit(self: @This()) void {
        self.gpa.free(self.script_pubkey);
    }
};

// TODO: This needs to be reviewed, I dont understand the read logic.
pub const Witness = struct {
    // The serialized witness.
    content: ArrayList(u8), // TODO: Could be a good candidate for []const u8

    // Number of elements in a witness.
    witness_elements: usize,

    // Index of the start of the last witness.
    last: usize,

    // Index of hte start of the second to last witness.
    second_to_last: usize,

    fn read(gpa: *mem.Allocator, reader: anytype) !Witness {
        const num_witnesses = try reader.readByte();
        var content = ArrayList(u8).init(gpa);
        errdefer content.deinit();

        var i: usize = 0;
        var last: usize = 0;
        while (i < num_witnesses) : (i += 1) {
            const witness_len = try reader.readByte();
            try content.append(witness_len);

            // Add 1 to the witness_len to include the varint of the witness.
            if (i == 0) {
                last = witness_len + 1;
            }

            const witness = try gpa.alloc(u8, witness_len);
            defer gpa.free(witness);
            _ = try reader.read(witness);

            try content.appendSlice(witness);
        }

        return Witness{
            .content = content,
            .witness_elements = num_witnesses,
            .last = last,
            .second_to_last = 0,
        };
    }

    fn write(self: @This(), writer: anytype) !void {
        try writer.writeIntLittle(u8, @intCast(u8, self.witness_elements));
        try writer.writeAll(self.content.items);
    }

    fn deinit(self: @This()) void {
        self.content.deinit();
    }
};

test "deserialize a segwit transaction" {
    // Segwit Transaction:
    // https://blockstream.info/tx/f5864806e3565c34d1b41e716f72609d00b55ea5eac5b924c9719a842ef42206
    // NOTE: I think it's a P2SH according to the block explorer?
    const tx_hex =
        "02000000" ++ // version
        "00" ++ // marker
        "01" ++ // segwit flag
        "01" ++ // number inputs
        "595895ea20179de87052b4046dfe6fd515860505d6511a9004cf12a1f93cac7c" ++ // prev_hash
        "01000000" ++ // prev_index
        "00" ++ // script sig len
        "ffffffff" ++ // sequence
        "01" ++ // number outputs
        "deb8070000000000" ++ // value of output
        "17" ++ // script pubkey len
        "a9140f3444e271620c736808aa7b33e370bd87cb5a0787" ++ // script_pubkey
        "02" ++ // number of witnesses
        "483045022100fb60dad8df4af2841adc0346638c16d0b8035f5e3f3753b88db122e70" ++ // witness0
        "c79f9370220756e6633b17fd2710e626347d28d60b0a2d6cbb41de51740644b9fb3ba7" ++
        "7510401" ++
        "21028fa937ca8cba2197a37c007176ed8941055d3bcb8627d085e94553e62f057dcc" ++ // witness1
        "00000000"; // lock time

    var buf: [1024]u8 = undefined;
    const tx_bytes = try fmt.hexToBytes(&buf, tx_hex);
    const tx = try Transaction.read(
        testing.allocator,
        io.fixedBufferStream(tx_bytes).reader(),
    );
    defer tx.deinit();

    // Assert the transaction is deserialized correctly.
    try testing.expectEqual(tx.version, 2);
    const inputs = tx.inputs.items;
    try testing.expectEqual(inputs.len, 1);

    // TODO CCDLE12: The prev hash is sent as LE but they are represented as BE?
    const prev_txid = try fmt.hexToBytes(
        &buf,
        "7cac3cf9a112cf04901a51d605058615d56ffe6d04b45270e89d1720ea955859",
    );
    try testing.expectEqualSlices(u8, &inputs[0].previous_output.txid, prev_txid);
    try testing.expectEqual(inputs[0].previous_output.vout, 1);
    try testing.expectEqual(inputs[0].script_sig.len, 0);
    try testing.expectEqual(inputs[0].sequence, 0xFFFFFFFF);
    try testing.expectEqual(inputs[0].witness.?.witness_elements, 2);
    try testing.expectEqual(inputs[0].witness.?.content.items.len, 107);
    try testing.expectEqual(inputs[0].witness.?.last, 73);
    try testing.expectEqual(inputs[0].witness.?.second_to_last, 0);
    const witness = try fmt.hexToBytes(&buf, "483045022100fb60dad8df4af2841adc" ++
        "0346638c16d0b8035f5e3f3753b88db122e70c79f9370220756e6633b17fd2710e626" ++
        "347d28d60b0a2d6cbb41de51740644b9fb3ba7751040121028fa937ca8cba2197a37c" ++
        "007176ed8941055d3bcb8627d085e94553e62f057dcc");
    try testing.expectEqualSlices(
        u8,
        inputs[0].witness.?.content.items,
        witness,
    );

    const outputs = tx.outputs.items;
    try testing.expectEqual(outputs.len, 1);
    // TODO: Should maybe convert this to full satoshis representation?
    try testing.expectEqual(outputs[0].value, 506078);
    try testing.expectEqual(outputs[0].script_pubkey.len, 23);
    try testing.expectEqualSlices(
        u8,
        outputs[0].script_pubkey,
        try fmt.hexToBytes(&buf, "a9140f3444e271620c736808aa7b33e370bd87cb5a0787"),
    );
    try testing.expectEqual(tx.lock_time, 0);

    // Test the transaction serializes back to the correct bytes.
    var serialized = ArrayList(u8).init(testing.allocator);
    defer serialized.deinit();
    try tx.write(serialized.writer());
    try testing.expectEqualSlices(
        u8,
        try fmt.hexToBytes(&buf, tx_hex),
        serialized.items,
    );

    // Test hashing a transaction that does not include the witness (default behaviour).
    const expected_tx_hash = "f5864806e3565c34d1b41e716f72609d00b55ea5eac5b924c9719a842ef42206";
    var tx_hash: U256 = undefined;
    try tx.txid(&tx_hash);
    try testing.expectEqualSlices(
        u8,
        try fmt.hexToBytes(&buf, expected_tx_hash),
        &tx_hash,
    );

    // Test hashing a tranaction that includes the witness.
    const expected_wtx_hash = "80b7d8a82d5d5bf92905b06f2014dd699e03837ca172e3a59d51426ebbe3e7f5";
    var wtx_hash: U256 = undefined;
    try tx.wtxid(&wtx_hash);
    try testing.expectEqualSlices(
        u8,
        try fmt.hexToBytes(&buf, expected_wtx_hash),
        &wtx_hash,
    );
}
