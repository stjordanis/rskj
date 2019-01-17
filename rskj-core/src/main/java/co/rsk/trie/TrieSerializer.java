/*
 * This file is part of RskJ
 * Copyright (C) 2019 RSK Labs Ltd.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with trie program. If not, see <http://www.gnu.org/licenses/>.
 */
package co.rsk.trie;

import co.rsk.crypto.Keccak256;
import co.rsk.panic.PanicProcessor;
import org.ethereum.crypto.Keccak256Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;

public class TrieSerializer {
    private static final Logger logger = LoggerFactory.getLogger(TrieSerializer.class);
    private static final PanicProcessor panicProcessor = new PanicProcessor();

    public byte[] invoke(Trie trie) {
        int lvalue = trie.getValueLength();
        int nnodes = trie.getNodeCount();
        int lshared = trie.getSharedPathLength();
        int lencoded = getEncodedPathLength(lshared);
        boolean hasLongVal = trie.hasLongValue();

        int bits = 0;

        for (int k = 0; k < TrieImpl.ARITY; k++) {
            Keccak256 nodeHash = trie.getHash(k);

            if (nodeHash == null) {
                continue;
            }

            bits |= 1 << k;
        }

        ByteBuffer buffer = ByteBuffer.allocate(TrieImpl.MESSAGE_HEADER_LENGTH + lencoded
                + nnodes * Keccak256Helper.DEFAULT_SIZE_BYTES
                + (hasLongVal ? (Keccak256Helper.DEFAULT_SIZE_BYTES+3) : lvalue));

        byte flags = 0;

        if (trie.isSecure()) {
            flags |= TrieImpl.ISSECURE_MASK;
        }

        if (hasLongVal) {
            flags |= TrieImpl.LONGVAL_MASK;
        }
        flags |=bits;
        buffer.put(flags);
        buffer.putShort((short) lshared);

        if (lshared > 0) {
            buffer.put(trie.getEncodedSharedPath());
        }

        for (int k = 0; k < TrieImpl.ARITY; k++) {
            Keccak256 nodeHash = trie.getHash(k);

            if (nodeHash == null) {
                continue;
            }

            buffer.put(nodeHash.getBytes());
        }

        if (lvalue > 0) {
            if (hasLongVal) {
                buffer.put(trie.getValueHash());
                encodeUInt24(buffer,trie.getValueLength());
            }
            else {
                buffer.put(trie.getValue());
            }
        }

        return buffer.array();
    }

    public static TrieImpl fromMessage(byte[] message, int position, int msglength, TrieStore store) {
        if (message == null) {
            return null;
        }

        ByteArrayInputStream bstream = new ByteArrayInputStream(message, position, msglength);
        DataInputStream istream = new DataInputStream(bstream);

        try {
            int flags = istream.readByte();
            boolean isSecure = (flags & TrieImpl.ISSECURE_MASK) !=0;
            boolean hasLongVal = (flags & TrieImpl.LONGVAL_MASK) !=0;
            int bhashes = flags;
            int lshared = istream.readShort();

            int nhashes = 0;
            int lencoded = TrieSerializer.getEncodedPathLength(lshared);

            byte[] encodedSharedPath = null;

            if (lencoded > 0) {
                encodedSharedPath = new byte[lencoded];
                if (istream.read(encodedSharedPath) != lencoded) {
                    throw new EOFException();
                }
            }

            Keccak256[] hashes = new Keccak256[TrieImpl.ARITY];

            for (int k = 0; k < TrieImpl.ARITY; k++) {
                if ((bhashes & (1 << k)) == 0) {
                    continue;
                }

                byte[] nodeHash = new byte[Keccak256Helper.DEFAULT_SIZE_BYTES];

                if (istream.read(nodeHash) != Keccak256Helper.DEFAULT_SIZE_BYTES) {
                    throw new EOFException();
                }

                hashes[k] = new Keccak256(nodeHash);
                nhashes++;
            }

            int offset = TrieImpl.MESSAGE_HEADER_LENGTH + lencoded + nhashes * Keccak256Helper.DEFAULT_SIZE_BYTES;
            byte[] value = null;
            int lvalue;
            byte[] valueHash = null;

            if (hasLongVal) {
                valueHash = new byte[Keccak256Helper.DEFAULT_SIZE_BYTES];

                if (istream.read(valueHash) != Keccak256Helper.DEFAULT_SIZE_BYTES) {
                    throw new EOFException();
                }

                // Now retrieve lvalue explicitely
                lvalue = readUInt24(istream);

                // This should be lazy: we don't need to retrieve the long value
                // until it's used.
                value = null;

            }
            else {
                lvalue = msglength - offset;

                if (lvalue > 0) {
                    value = new byte[lvalue];
                    if (istream.read(value) != lvalue) {
                        throw new EOFException();
                    }
                }
            }

            // TODO: THIS IS SHIT
            TrieImpl trie = new TrieImpl(encodedSharedPath, lshared, value, null,
                    hashes, store,lvalue,valueHash, isSecure);

            if (store != null) {
                trie.saved = true;
            }

            return trie;
        } catch (IOException ex) {
            logger.error(TrieImpl.ERROR_CREATING_TRIE, ex);
            panicProcessor.panic(TrieImpl.PANIC_TOPIC, TrieImpl.ERROR_CREATING_TRIE +": " + ex.getMessage());
            throw new TrieSerializationException(TrieImpl.ERROR_CREATING_TRIE, ex);
        }
    }

    private static int readUInt24(DataInputStream in ) throws IOException {
        // Big-Endigan
        int ch1 = in.read();
        int ch2 = in.read();
        int ch3 = in.read();
        if ((ch1 | ch2 | ch3) < 0) // detect -1 (EOF)
            throw new EOFException();
        return ((ch1 << 16) + (ch2 << 8) + (ch3 << 0));
    }

    protected static int getEncodedPathLength(int length) {
        return length / 8 + (length % 8 == 0 ? 0 : 1);
    }

    private static void encodeUInt24(ByteBuffer buffer, int len) {
        buffer.put((byte) ((len & 0x00FF0000) >> 16));
        buffer.put((byte) ((len & 0x0000FF00) >> 8));
        buffer.put((byte) ((len & 0X000000FF)));
    }
}
