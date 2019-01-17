/*
 * This file is part of RskJ
 * Copyright (C) 2017 RSK Labs Ltd.
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

import java.util.function.BiFunction;

/**
 * OldTrieImpl is the trie node.
 */
public class OldTrieImpl extends TrieImpl {

    public static final int MESSAGE_HEADER_LENGTH = 2 + Short.BYTES * 2;

    protected OldTrieImpl(byte[] encodedSharedPath,
                       int sharedPathLength, byte[] value, TrieImpl[] nodes,
                       Keccak256[] hashes, TrieStore store,
                       int valueLength,byte[] valueHash, boolean isSecure) {

        super(encodedSharedPath,sharedPathLength, value, nodes,
                hashes, store,valueLength, valueHash, isSecure);
    }

    public OldTrieImpl(boolean isSecure) {
        super(isSecure);
    }

    @Override
    protected TrieImpl getInstance(TrieStore store, boolean isSecure){
        return new OldTrieImpl(null, 0, null, null, null, store, 0, null, isSecure);
    }

    @Override
    protected TrieImpl getInstance(byte[] encodedSharedPath, int sharedPathLength, byte[] value, TrieImpl[] nodes,
                           Keccak256[] hashes, TrieStore store, int valueLength, byte[] valueHash, boolean isSecure) {
        return new OldTrieImpl(encodedSharedPath, sharedPathLength, value, nodes, hashes, store, valueLength, valueHash, isSecure);
    }

    /**
     * toMessage serialize the node to bytes. Used to persist the node in a key-value store
     * like levelDB or redis.
     *
     * The serialization includes:
     * - arity: byte
     * - bits with present hashes: two bytes (example: 0x0203 says that the node has
     * hashes at index 0, 1, 9 (the other subnodes are null)
     * - present hashes: 32 bytes each
     * - associated value: remainder bytes (no bytes if null)
     *
     * @return a byte array with the serialized info
     */
    @Override
    public byte[] toMessage() {
        return new OldTrieSerializer().invoke(this);
    }

    @Override
    public BiFunction<byte[], TrieStore, Trie> fromMessageFunction() {
        return OldTrieImpl::fromMessage;
    }

    public static OldTrieImpl fromMessage(byte[] message, TrieStore store) {
        if (message == null) {
            return null;
        }

        return fromMessage(message, 0, message.length, store);
    }


    private static OldTrieImpl fromMessage(byte[] message, int position, int msglength, TrieStore store) {
        return OldTrieSerializer.fromMessage(message, position, msglength, store);
    }
}
