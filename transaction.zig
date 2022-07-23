const std = @import("std");
const consensus = @import("./consensus.zig");
const hash = @import("./hash.zig");
const types = @import("./types.zig");

const fmt = std.fmt;
const io = std.io;
const mem = std.mem;
const testing = std.testing;

const ArrayList = std.ArrayList;
const witness_scale_factor = consensus.witness_scale_factor;
const double_sha256 = hash.double_sha256;
const U256 = hash.U256;
const VarInt = types.VarInt;

pub const Transaction = struct {
    /// The protocol version (2 is the current default).
    version: i32 = 2,

    /// Transaction inputs that fund a transaction.
    inputs: ArrayList(TxIn),

    /// Transaction outputs used to transfer ownership of coins to the receivers.
    outputs: ArrayList(TxOut),

    /// The time that a transaction is locked until a specific block height or
    /// a future point in time (Unix).
    ///
    /// e.g.
    ///     lock_time < 500000000 is block height
    ///     lock_time >= 500000000 is unix timestamp
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

        var is_segwit = false;
        const inputs_len = blk: {
            var len = try VarInt.read(reader);

            // This is a Segwit transaction because 0x00 is set as the marker byte.
            if (len.inner == 0x00) {
                is_segwit = true;

                const segwit_flag = try reader.readIntNative(u8);
                if (segwit_flag != 0x01) return Transaction.Error.InvalidSegwitFlag;

                // The next byte should be the length of inputs for Segwit txs.
                len = try VarInt.read(reader);
            }

            break :blk len;
        };

        var inputs = blk: {
            var in = std.ArrayList(TxIn).init(gpa);

            var i: usize = 0;
            while (i < inputs_len.inner) : (i += 1)
                try in.append(try TxIn.read(gpa, reader));

            break :blk in;
        };

        // TODO: The witness comes later in the tx, need to assign them to the correct inputs later?
        const outputs = blk: {
            const outputs_len = try VarInt.read(reader);
            var out = std.ArrayList(TxOut).init(gpa);

            var i: usize = 0;
            while (i < outputs_len.inner) : (i += 1)
                try out.append(try TxOut.read(gpa, reader));

            break :blk out;
        };

        // TODO:
        // - Assign to inputs, but how do we know if we have multiple???
        // - input[0].witness = witness;
        if (is_segwit) {
            const witness = try Witness.read(gpa, reader);
            inputs.items[0].witness = witness;
        }

        const lock_time = try reader.readIntNative(u32);

        return Transaction{
            .version = version,
            .inputs = inputs,
            .outputs = outputs,
            .lock_time = lock_time,
            .gpa = gpa,
        };
    }

    /// Serializes the Transaction and by default, adheres to Segwit.
    /// Segwit BIP-141: https://github.com/bitcoin/bips/blob/master/bip-0141.mediawikik
    fn write(self: Transaction, writer: anytype) !void {
        try self.internal_write(writer, true);
    }

    /// internal_write() contains a parameter: "include_witness". This allows
    /// the caller to include the Segwit marker bytes and the witness data in the
    /// serialized output.
    ///
    /// Serializing the tx has x2 main purposes:
    ///     - Generating a tx hash
    ///     - Serializing the tx for inclusion in a block
    ///
    /// For hashing purposes, "include_witness" is false by default, indicating
    /// adherence to Segwit (hashing the tx WITHOUT Segwit marker bytes and witnesses).
    ///
    /// For serializing the tx for inclusion in a block, "include_witness" is true 
    /// by default, since we MUST include the Segwit marker bytes and the witness
    /// data.
    fn internal_write(self: Transaction, writer: anytype, include_witness: bool) !void {
        try writer.writeIntLittle(i32, self.version);

        var is_segwit = false;
        for (self.inputs.items) |input| {
            if (input.witness) |_| {
                is_segwit = true;
                break;
            }
        }

        // Add the marker bytes to indicate the tx is Segwit.
        if (is_segwit and include_witness) {
            try writer.writeIntLittle(u8, 0x00);
            try writer.writeIntLittle(u8, 0x01);
        }

        try VarInt.init(self.inputs.items.len).write(writer);
        for (self.inputs.items) |input| try input.write(writer);

        try VarInt.init(self.outputs.items.len).write(writer);
        for (self.outputs.items) |output| try output.write(writer);

        // Assign the segregated witness data, linked to each input.
        if (is_segwit and include_witness) {
            for (self.inputs.items) |input| try input.witness.?.write(writer);
        }

        try writer.writeIntLittle(u32, self.lock_time);
    }

    /// Returns the tx hash that does NOT include the witness data (Segwit). This
    /// is the default behaviour and should be used for all transactions.
    fn txid(self: Transaction, output: *U256) !void {
        try self.internal_hash(output, false);
    }

    /// Returns the tx hash that includes the witness data (Legacy format).
    fn wtxid(self: Transaction, output: *U256) !void {
        try self.internal_hash(output, true);
    }

    /// Hash function that serializes the tx and then hashes to the location
    /// of the U256 output.
    fn internal_hash(self: Transaction, output: *U256, include_witness: bool) !void {
        var serialized = ArrayList(u8).init(self.gpa);
        defer serialized.deinit();

        try self.internal_write(serialized.writer(), include_witness);

        double_sha256(serialized.items, output);
        mem.reverse(u8, output);
    }

    /// Returns the weight of the tx. This method is able to add the Segwit 
    /// weights if the tx is Segwit.
    fn weight(self: Transaction) usize {
        return self.internal_scale_size(witness_scale_factor, true);
    }

    /// Returns the actual serialized byte size of the tx, byte for byte.
    fn size(self: Transaction) usize {
        return self.internal_scale_size(1, true);
    }

    /// Returns the virtual size of the tx. This is an alternative measurement
    /// of the bytes, where one vbyte is equal to four weight units.
    fn vsize(self: Transaction) !usize {
        return try std.math.divCeil(usize, self.weight(), witness_scale_factor);
    }

    /// The size of a tx without witness data.
    fn stripped_size(self: Transaction) usize {
        return self.internal_scale_size(1, false);
    }

    /// Returns the size of the serialized tx according to a particular
    /// scale factor. This can be used to calculate the weight of the tx given 
    /// the witness scale factor or a weight of 1-to-1 per byte.
    ///
    /// "include_witness" flag allows the witness to be ignored when calculating
    /// the transaction size, even if the witness exists.
    fn internal_scale_size(self: Transaction, scale_factor: usize, include_witness: bool) usize {
        var input_weight: usize = 0;
        var inputs_with_witnesses: usize = 0;
        for (self.inputs.items) |input| {
            // Multiply non-segwit bytes by the scale_factor to apply the weight
            // per bytes.
            input_weight += scale_factor * input.serialized_len();

            // Add Segwit bytes without applying the scale factor, each Segwit
            // byte has only 1 weight.
            if (include_witness) {
                if (input.witness) |witness| {
                    inputs_with_witnesses += 1;
                    input_weight += witness.serialized_len();
                }
            }
        }

        // If this is a Segwit transaction, add 2 bytes at 1 weight each to
        // reflect the Segwit marker byte and Segwit flag byte in the tx.
        if (inputs_with_witnesses > 0) input_weight += 2;

        // Sum all other non-Segwit bytes and apply the scale_factor for the
        // weight.
        var output_size: usize = 0;
        for (self.outputs.items) |output|
            output_size += output.serialized_len();

        const non_input_weight = scale_factor *
            (@sizeOf(@TypeOf(self.version)) +
            VarInt.init(self.inputs.items.len).size() +
            VarInt.init(self.outputs.items.len).size() +
            output_size +
            @sizeOf(@TypeOf(self.lock_time)));

        const total_weight = input_weight + non_input_weight;
        return total_weight;
    }

    fn deinit(self: Transaction) void {
        for (self.inputs.items) |input| input.deinit();
        self.inputs.deinit();

        for (self.outputs.items) |output| output.deinit();
        self.outputs.deinit();
    }
};

/// Transaction Input used to reference previously unspent coins.
pub const TxIn = struct {
    /// The previous transaction output that is going to be used.
    previous_output: OutPoint,

    /// The opcodes as bytes used in the unlocking script to access the previous_output.
    script_sig: ArrayList(u8),

    /// Used to prioritize conflicting transactions. By default, it will be set to
    /// 0xFFFFFFFF meaning this feature is not being used.
    sequence: u32 = 0xFFFFFFFF,

    /// TODO: Witness data comments
    witness: ?Witness,

    gpa: *mem.Allocator,

    /// TODO: comments
    fn serialized_len(self: @This()) usize {
        const script_sig_len = blk: {
            var len = VarInt.init(self.script_sig.items.len).size();
            if (self.script_sig.items.len > 0)
                len = self.script_sig.items.len;

            break :blk len;
        };

        return self.previous_output.serialized_len() +
            script_sig_len +
            @sizeOf(@TypeOf(self.sequence));
    }

    fn read(gpa: *mem.Allocator, reader: anytype) !TxIn {
        const previous_output = try OutPoint.read(reader);

        var script_sig = ArrayList(u8).init(gpa);
        errdefer script_sig.deinit();

        const script_sig_len = try reader.readByte();
        if (script_sig_len > 0) {
            try script_sig.append(script_sig_len);

            var i: usize = 0;
            while (i < script_sig_len) : (i += 1) {
                const byte = try reader.readByte();
                try script_sig.append(byte);
            }
        }

        return TxIn{
            .previous_output = previous_output,
            .script_sig = script_sig,
            .sequence = try reader.readIntNative(u32),
            .witness = null,
            .gpa = gpa,
        };
    }

    fn write(self: @This(), writer: anytype) !void {
        try self.previous_output.write(writer);

        if (self.script_sig.items.len > 0) {
            try writer.writeAll(self.script_sig.items);
        } else {
            try writer.writeIntLittle(u8, 0);
        }

        try writer.writeIntLittle(u32, self.sequence);
    }

    pub fn deinit(self: @This()) void {
        self.script_sig.deinit();
        if (self.witness) |w| w.deinit();
    }
};

// A reference to a previous Transaction Output used in Transaction Inputs.
pub const OutPoint = struct {
    // TODO CCDLE12: This should be reversed
    // The tranaction id that's being referenced.
    txid: U256,

    // The index position of the referenced previous output in the transactions output.
    vout: u32,

    fn read(reader: anytype) !OutPoint {
        // TODO: Make sure I know exactly why the txid is littleendian/bigendian
        // txid needs to be reversed.
        var txid = try reader.readBytesNoEof(32);
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

    // TODO TMP: comments
    fn serialized_len(self: @This()) usize {
        return self.txid.len + @sizeOf(@TypeOf(self.vout));
    }
};

// Transaction Ouput contains a numeric value representing a transfer of Bitcoin
// and a challenge for the receiver to prove ownership over the Bitcoin. The receiver
// would consume the TxOut as a TxIn in a subsequent Transaction.
pub const TxOut = struct {
    // The value of the transaction output in satoshis.
    value: u64,

    // The locking script of the transaction output.
    script_pubkey: ArrayList(u8),

    gpa: *mem.Allocator,

    fn serialized_len(self: @This()) usize {
        return @sizeOf(@TypeOf(self.value)) +
            self.script_pubkey.items.len;
    }

    fn read(gpa: *mem.Allocator, reader: anytype) !TxOut {
        const value = try reader.readIntNative(u64);

        var script_pubkey = ArrayList(u8).init(gpa);
        errdefer script_pubkey.deinit();

        const script_pubkey_len = try reader.readByte();
        try script_pubkey.append(script_pubkey_len);

        var i: usize = 0;
        while (i < script_pubkey_len) : (i += 1) {
            const byte = try reader.readByte();
            try script_pubkey.append(byte);
        }

        return TxOut{
            .value = value,
            .script_pubkey = script_pubkey,
            .gpa = gpa,
        };
    }

    fn write(self: @This(), writer: anytype) !void {
        try writer.writeIntLittle(u64, self.value);
        try writer.writeAll(self.script_pubkey.items);
    }

    pub fn deinit(self: @This()) void {
        self.script_pubkey.deinit();
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

    fn serialized_len(self: @This()) usize {
        return VarInt.init(self.witness_elements).size() +
            self.content.items.len;
    }

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
            if (i == 0) last = witness_len + 1;

            var j: usize = 0;
            while (j < witness_len) : (j += 1) {
                const byte = try reader.readByte();
                try content.append(byte);
            }
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

test "non-segwit P2PKH tx" {
    const tx_hex =
        "02000000" ++ // version
        "01" ++ // number of inputs
        "855f90bf2f355457fb5c294f820457822a818c301bc8a395ca44209f8a6df768" ++ // prev_hash
        "00000000" ++ // prev_index
        "6a47304402207c8e61ffe680f21725e4e79306830b76e58b1b42f75f70a117c0fd6532a9e8960220536293629339a41ae72b23098ced2fe48425f94f7711b37ad466884bc02e4cef0121023abc81b1328f631fd90aca9d6eade0b260758deb9c6a1805915f1dc1491afd2e" ++ // script_sig
        "fdffffff" ++ // sequence number
        "01" ++ // number outputs
        "5397000000000000" ++ // value of output
        "1976a914f36e80fa8a3f3b2b6b2bf3f4daa428099206157888ac" ++ // script_pubkey
        "d6c60800"; // lock time

    // Deserialize the tx hex bytes into a Transaction.
    var buf: [1024]u8 = undefined;
    const tx_bytes = try fmt.hexToBytes(&buf, tx_hex);

    const tx = try Transaction.read(
        testing.allocator,
        io.fixedBufferStream(tx_bytes).reader(),
    );
    defer tx.deinit();

    // Assert that the tx can be serialized back to the original tx_hex.
    var serialized = ArrayList(u8).init(testing.allocator);
    defer serialized.deinit();
    try tx.write(serialized.writer());

    // var ser_bytes: [1024]u8 = undefined;
    try testing.expectEqualSlices(
        u8,
        try fmt.hexToBytes(&buf, tx_hex),
        serialized.items,
    );

    // Assert the correct txid can be generated.
    var tx_hash: U256 = undefined;
    try tx.txid(&tx_hash);

    const expected_tx_hash = try fmt.hexToBytes(&buf, "0556e5e4206759d0114151c27b67ffb593b0c05ea25a2a5f0d52b161687a4061");
    try testing.expectEqualSlices(u8, &tx_hash, expected_tx_hash);

    // Assert the tx inputs are deserialized correctly.
    try testing.expectEqual(tx.version, 2);
    const inputs = tx.inputs.items;
    try testing.expectEqual(inputs.len, 1);

    var prev_txid = try fmt.hexToBytes(&buf, "855f90bf2f355457fb5c294f820457822a818c301bc8a395ca44209f8a6df768");
    mem.reverse(u8, prev_txid);

    try testing.expectEqualSlices(u8, &inputs[0].previous_output.txid, prev_txid);
    try testing.expectEqual(inputs[0].previous_output.vout, 0);
    try testing.expectEqual(inputs[0].script_sig.items.len, 107);
    try testing.expectEqualSlices(u8, inputs[0].script_sig.items, try fmt.hexToBytes(&buf, "6a47304402207c8e61ffe680f21725e4e79306830b76e58b1b42f75f70a117c0fd6532a9e8960220536293629339a41ae72b23098ced2fe48425f94f7711b37ad466884bc02e4cef0121023abc81b1328f631fd90aca9d6eade0b260758deb9c6a1805915f1dc1491afd2e"));
    try testing.expectEqual(inputs[0].sequence, 0xFFFFFFFD);
    try testing.expectEqual(inputs[0].witness, null);

    // Assert the tx outputs are deserialized correctly.
    const outputs = tx.outputs.items;
    try testing.expectEqual(outputs.len, 1);

    try testing.expectEqual(outputs[0].value, 38739);
    try testing.expectEqual(outputs[0].script_pubkey.items.len, 26);
    try testing.expectEqualSlices(
        u8,
        outputs[0].script_pubkey.items,
        try fmt.hexToBytes(&buf, "1976a914f36e80fa8a3f3b2b6b2bf3f4daa428099206157888ac"),
    );
    try testing.expectEqual(tx.lock_time, 575190);

    // Test the weight calculations for the transaction are accurate.
    const expected_weight = 764;
    try testing.expectEqual(tx.weight(), expected_weight);
    try testing.expectEqual(tx.size(), tx_bytes.len);
    try testing.expectEqual(tx.vsize(), 191);
}

test "deserialize a Segwit transaction" {
    // Segwit Transaction:
    // https://blockstream.info/tx/f5864806e3565c34d1b41e716f72609d00b55ea5eac5b924c9719a842ef42206
    // NOTE: I think it's a P2SH according to the block explorer?
    const tx_hex =
        "02000000" ++ // version
        "00" ++ // marker
        "01" ++ // Segwit flag
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

    // Assert the tx inputs are deserialized correctly.
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
    try testing.expectEqual(inputs[0].script_sig.items.len, 0);
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

    // Assert the tx outputs are deserialized correctly.
    const outputs = tx.outputs.items;
    try testing.expectEqual(outputs.len, 1);

    // TODO: Should maybe convert this to full satoshis representation?
    try testing.expectEqual(outputs[0].value, 506078);
    try testing.expectEqual(outputs[0].script_pubkey.items.len, 24);
    try testing.expectEqualSlices(
        u8,
        outputs[0].script_pubkey.items,
        try fmt.hexToBytes(&buf, "17a9140f3444e271620c736808aa7b33e370bd87cb5a0787"),
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

    // Test hashing a transaction that includes the witness.
    const expected_wtx_hash = "80b7d8a82d5d5bf92905b06f2014dd699e03837ca172e3a59d51426ebbe3e7f5";

    var wtx_hash: U256 = undefined;
    try tx.wtxid(&wtx_hash);

    try testing.expectEqualSlices(
        u8,
        try fmt.hexToBytes(&buf, expected_wtx_hash),
        &wtx_hash,
    );

    // Test the weight calculations for the transaction is accurate.
    const expected_weight = 442;
    try testing.expectEqual(tx.weight(), expected_weight);
    try testing.expectEqual(tx.size(), tx_bytes.len);
    try testing.expectEqual(tx.vsize(), 111);

    // Test the stripped_size() can be returned correctly.
    const expected_strippedsize = (expected_weight - tx_bytes.len) / (witness_scale_factor - 1);
    try testing.expectEqual(tx.stripped_size(), expected_strippedsize);
}
