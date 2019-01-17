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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

public class OldTrieSerializer {
    private static final Logger logger = LoggerFactory.getLogger(OldTrieSerializer.class);
    private static final PanicProcessor panicProcessor = new PanicProcessor();

    public byte[] invoke(Trie trie) {
        int lvalue = trie.getValueLength();
        //int nnodes = this.getNodeCount();
        int lshared = trie.getSharedPathLength();
        int lencoded = TrieSerializer.getEncodedPathLength(lshared);
        boolean hasLongVal = trie.hasLongValue();

        int bits = 0;
        int nnodes = 0;

        for (int k = 0; k < OldTrieImpl.ARITY; k++) {
            Keccak256 nodeHash = trie.getHash(k);

            if (nodeHash == null) {
                continue;
            }
            nnodes++;
            bits |= 1 << k;
        }

        ByteBuffer buffer = ByteBuffer.allocate(
                OldTrieImpl.MESSAGE_HEADER_LENGTH +
//                        (lshared > 0 ? lencoded:0) + // TODO: check if lencoded is 0 when lshared is zero
                        (lshared > 0 ? lencoded:0) + // TODO: check if lencoded is 0 when lshared is zero
                        nnodes * Keccak256Helper.DEFAULT_SIZE_BYTES +
                        (hasLongVal ? Keccak256Helper.DEFAULT_SIZE_BYTES : lvalue)); //TODO check lvalue == 0 case

        buffer.put((byte) OldTrieImpl.ARITY);

        byte flags = 0;

        if (trie.isSecure()) {
            flags |= 1;
        }

        if (hasLongVal) {
            flags |= 2;
        }

        buffer.put(flags);
        buffer.putShort((short) bits);
        buffer.putShort((short) lshared);

        if (lshared > 0) {
            buffer.put(trie.getEncodedSharedPath());
        }

        for (int k = 0; k < OldTrieImpl.ARITY; k++) {
            Keccak256 nodeHash = trie.getHash(k);

            if (nodeHash == null) {
                continue;
            }

            buffer.put(nodeHash.getBytes());
        }

        if (lvalue > 0) {
            if (hasLongVal) {
                buffer.put(trie.getValueHash());
            }
            else {
                buffer.put(trie.getValue());
            }
        }

        return buffer.array();
    }


    public static OldTrieImpl fromMessage(byte[] message, int position, int msglength, TrieStore store) {
        if (message == null) {
            return null;
        }

        ByteArrayInputStream bstream = new ByteArrayInputStream(message, position, msglength);
        DataInputStream istream = new DataInputStream(bstream);

        try {
            int arity = istream.readByte();

            if (arity != OldTrieImpl.ARITY) {
                throw new IllegalArgumentException(OldTrieImpl.INVALID_ARITY);
            }

            int flags = istream.readByte();
            boolean isSecure = (flags & 0x01) == 1;
            boolean hasLongVal = (flags & 0x02) == 2;
            int bhashes = istream.readShort();
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

            Keccak256[] hashes = new Keccak256[arity];

            for (int k = 0; k < arity; k++) {
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

            int offset = OldTrieImpl.MESSAGE_HEADER_LENGTH + lencoded + nhashes * Keccak256Helper.DEFAULT_SIZE_BYTES;
            byte[] value = null;
            int lvalue;
            byte[] valueHash = null;

            if (hasLongVal) {
                valueHash = new byte[Keccak256Helper.DEFAULT_SIZE_BYTES];

                if (istream.read(valueHash) != Keccak256Helper.DEFAULT_SIZE_BYTES) {
                    throw new EOFException();
                }

                value = store.retrieveValue(valueHash);
                lvalue = value.length;
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

            OldTrieImpl trie = new OldTrieImpl(encodedSharedPath, lshared, value, null,
                    hashes, store,lvalue,valueHash, isSecure);

            if (store != null) {
                trie.saved = true;
            }

            return trie;
        } catch (IOException ex) {
            logger.error(OldTrieImpl.ERROR_CREATING_TRIE, ex);
            panicProcessor.panic(OldTrieImpl.PANIC_TOPIC, OldTrieImpl.ERROR_CREATING_TRIE +": " + ex.getMessage());
            throw new TrieSerializationException(OldTrieImpl.ERROR_CREATING_TRIE, ex);
        }
    }
}
