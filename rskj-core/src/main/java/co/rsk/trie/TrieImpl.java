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
import co.rsk.panic.PanicProcessor;
import co.rsk.util.Pair;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;
import org.ethereum.crypto.Keccak256Helper;
import org.ethereum.datasource.HashMapDB;
import org.ethereum.db.ByteArrayWrapper;
import org.ethereum.util.RLP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Stream;

import static org.ethereum.util.ByteUtil.EMPTY_BYTE_ARRAY;

/**
 * TrieImpl is the trie node.
 *
 * Each node have 2, 4 or 16 subnodes (depending on arity variable value)
 * and an optional associated value (a byte array)
 *
 * A node is referenced via a key (a byte array)
 *
 * A node can be serialized to/from a message (a byte array)
 *
 * A node has a hash (Sha3 of its serialization)
 *
 * A node is immutable: to add/change a value or key, a new node is created
 *
 * An empty node has no subnodes and a null value
 *
 * Created by ajlopez on 22/08/2016.
 */
public class TrieImpl implements Trie {
    protected static final int ARITY = 2;

    protected static final Logger logger = LoggerFactory.getLogger("newtrie");
    protected static final PanicProcessor panicProcessor = new PanicProcessor();
    protected static final String PANIC_TOPIC = "newtrie";
    protected static final String INVALID_ARITY = "Invalid arity";
    protected static final String INVALID_VALUE_LENGTH = "Invalid value length";
    protected static final String ERROR_CREATING_TRIE = "Error creating trie from message";
    protected static final String ERROR_NON_EXISTENT_TRIE_LOGGER = "Error non existent trie with hash {}";
    protected static final String ERROR_NON_EXISTENT_TRIE = "Error non existent trie with hash ";

    private static final int MESSAGE_HEADER_LENGTH = 2 + Short.BYTES * 2;
    private static final int SERIALIZATION_HEADER_LENGTH = Short.BYTES * 2 + Integer.BYTES * 2;
    private static final int ISSECURE_MASK = 64;
    private static final int LONGVAL_MASK = 32;

    // all zeroed, default hash for empty nodes
    private static Keccak256 emptyHash = makeEmptyHash();

    // this node associated value, if any
    protected byte[] value;

    // the list of subnodes
    protected TrieImpl[] nodes;

    // the list of subnode hashes
    protected Keccak256[] hashes;

    // this node hash value
    protected Keccak256 hash;

    // it is saved to store
    protected boolean saved;

    // sha3 is applied to keys
    protected boolean isSecure;

    // valueLength enables lazy long value retrieval.
    // The length of the data is now stored. This allows EXTCODESIZE to
    // execute much faster without the need to actually retrieve the data.
    // if valueLength>32 and value==null this means the value has not been retrieved yet.
    // if valueLength==0, then there is no value AND no node.
    // This trie structure does not distinguish between empty arrays
    // and nulls. Storing an empty byte array has the same effect as removing the node.
    //
    protected int valueLength;

    // For lazy retrieval and also for cache.
    protected byte[] valueHash;

    // associated store, to store or retrieve nodes in the trie
    protected TrieStore store;

    // shared Path
    protected byte[] encodedSharedPath;
    protected int sharedPathLength;

    // default constructor, no secure
    public TrieImpl() {
        this(null, 0, null, null, null, null,0,null);
        this.isSecure = false;
    }

    public TrieImpl(boolean isSecure) {
        this(null, 0, null, null, null, null,0,null);
        this.isSecure = isSecure;
    }

    public TrieImpl(TrieStore store, boolean isSecure) {
        this(null, 0, null, null, null, store,0,null);
        this.isSecure = isSecure;
    }

    protected TrieImpl(TrieStore store, byte[] encodedSharedPath, int sharedPathLength,
                     byte[] value, boolean isSecure,
                     int valueLength,byte[] valueHash) {
        this(encodedSharedPath, sharedPathLength, value, null, null, store,valueLength,valueHash);
        this.isSecure = isSecure;
    }

    // full constructor
    protected TrieImpl(byte[] encodedSharedPath,
                     int sharedPathLength, byte[] value, TrieImpl[] nodes,
                     Keccak256[] hashes, TrieStore store,
                     int valueLength,byte[] valueHash) {
        this.value = value;
        this.nodes = nodes;
        this.hashes = hashes;
        this.store = store;
        this.encodedSharedPath = encodedSharedPath;
        this.sharedPathLength = sharedPathLength;
        this.valueLength = valueLength;
        this.valueHash = valueHash;
        checkValueLength();
    }

    protected TrieImpl withSecure(boolean isSecure) {
        this.isSecure = isSecure;
        return this;
    }

    @Override
    public boolean isSecure() {
        return isSecure;
    }

    private Trie cloneTrie() {
        return new TrieImpl(this.encodedSharedPath, this.sharedPathLength, this.value, cloneNodes(true), cloneHashes(), this.store,this.valueLength,this.valueHash).withSecure(this.isSecure);
    }

    /**
     * Pool method, to create a NewTrie from a serialized message
     * the store argument is used to retrieve any subnode
     * of the subnode
     *
     * @param message   the content (arity, hashes, value) serializaced as byte array
     * @param store     the store containing the rest of the trie nodes, to be used on retrieve them if they are needed in memory
     */
    public static TrieImpl fromMessage(byte[] message, TrieStore store) {
        if (message == null) {
            return null;
        }

        return fromMessage(message, 0, message.length, store);
    }


    private static TrieImpl fromMessage(byte[] message, int position, int msglength, TrieStore store) {
        if (message == null) {
            return null;
        }

        ByteArrayInputStream bstream = new ByteArrayInputStream(message, position, msglength);
        DataInputStream istream = new DataInputStream(bstream);

        try {
            int arity = istream.readByte();

            if (arity != ARITY) {
                throw new IllegalArgumentException(INVALID_ARITY);
            }

            int flags = istream.readByte();
            boolean isSecure = (flags & 0x01) == 1;
            boolean hasLongVal = (flags & 0x02) == 2;
            int bhashes = istream.readShort();
            int lshared = istream.readShort();

            int nhashes = 0;
            int lencoded = TrieImpl.getEncodedPathLength(lshared);

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

            int offset = MESSAGE_HEADER_LENGTH + lencoded + nhashes * Keccak256Helper.DEFAULT_SIZE_BYTES;
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

            TrieImpl trie = new TrieImpl(encodedSharedPath, lshared, value, null,
                    hashes, store,lvalue,valueHash).withSecure(isSecure);

            if (store != null) {
                trie.saved = true;
            }

            return trie;
        } catch (IOException ex) {
            logger.error(ERROR_CREATING_TRIE, ex);
            panicProcessor.panic(PANIC_TOPIC, ERROR_CREATING_TRIE +": " + ex.getMessage());
            throw new TrieSerializationException(ERROR_CREATING_TRIE, ex);
        }
    }

    /**
     * getHash calculates and/or returns the hash associated with this node content
     *
     * the internal variable hash could contains the cached hash.
     *
     * This method is not synchronized because the result of it's execution
     *
     * disregarding the lazy initialization is idempotent. It's better to keep
     *
     * it out of synchronized.
     *
     * @return  a byte array with the node serialized to bytes
     */
    @Override
    public Keccak256 getHash() {
        if (this.hash != null) {
            return this.hash.copy();
        }

        if (isEmptyTrie(this.valueLength, this.nodes, this.hashes)) {
            return emptyHash.copy();
        }

        byte[] message = this.toMessage();

        this.hash = new Keccak256(Keccak256Helper.keccak256(message));

        return this.hash.copy();
    }

    /**
     * get returns the value associated with a key
     *
     * @param key the key associated with the value, a byte array (variable length)
     *
     * @return  the associated value, a byte array, or null if there is no associated value to the key
     */
    @Override
    public byte[] get(byte[] key) {
        ExpandedKey keyBytes = ExpandedKey.expandKey(key);
        return get(keyBytes, keyBytes.length(), 0);
    }

    /**
     * get by string, utility method used from test methods
     *
     * @param key   a string, that is converted to a byte array
     * @return a byte array with the associated value
     */
    @Override
    public byte[] get(String key) {
        return this.get(key.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * put key value association, returning a new NewTrie
     *
     * @param key   key to be updated or created, a byte array
     * @param value value to associated to the key, a byte array
     *
     * @return a new NewTrie node, the top node of the new tree having the
     * key-value association. The original node is immutable, a new tree
     * is build, adding some new nodes
     */
    @Override
    public Trie put(byte[] key, byte[] value) {
        ExpandedKey keyBytes = ExpandedKey.expandKey(key);
        Trie trie = put(keyBytes, keyBytes.length(), 0, value);

        return trie == null ? new TrieImpl(this.store, this.isSecure) : trie;
    }

    @Override
    public Trie put(ByteArrayWrapper key, byte[] value) {
        return put(key.getData(),value);
    }
    /**
     * put string key to value, the key is converted to byte array
     * utility method to be used from testing
     *
     * @param key   a string
     * @param value an associated value, a byte array
     *
     * @return  a new NewTrie, the top node of a new trie having the key
     * value association
     */
    @Override
    public Trie put(String key, byte[] value) {
        return put(key.getBytes(StandardCharsets.UTF_8), value);
    }

    /**
     * delete update the key to null value
     *
     * @param key   a byte array
     *
     * @return the new top node of the trie with the association removed
     *
     */
    @Override
    public Trie delete(byte[] key) {
        return put(key, null);
    }

    @Override
    // This is O(1). The node with exact key "key" MUST exists.
    public Trie deleteRecursive(byte[] key) {
        //ExpandedKey keyBytes = bytesToExpandedKey(key);

        /* Something Angel must do here !*/
        /* Something Angel must do here !*/
        /* Something Angel must do here !*/
        /* Something Angel must do here !*/
        /* Something Angel must do here !*/
        // do a node delete just to pass tests

        return delete(key);
    }

    /**
     * delete string key, utility method to be used for testing
     *
     * @param key a string
     *
     * @return the new top node of the trie with the key removed
     */
    @Override
    public Trie delete(String key) {
        return delete(key.getBytes(StandardCharsets.UTF_8));
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
        int lvalue = this.valueLength;
        //int nnodes = this.getNodeCount();
        int lshared = this.sharedPathLength;
        int lencoded = getEncodedPathLength(lshared);
        boolean hasLongVal = this.hasLongValue();

        int bits = 0;
        int nnodes = 0;

        for (int k = 0; k < ARITY; k++) {
            Keccak256 nodeHash = this.getHash(k);

            if (nodeHash == null) {
                continue;
            }
            nnodes++;
            bits |= 1 << k;
        }

        ByteBuffer buffer = ByteBuffer.allocate(MESSAGE_HEADER_LENGTH  + (lshared > 0 ? lencoded: 0) // TODO: check if lencoded is 0 when lshared is zero
                + nnodes * Keccak256Helper.DEFAULT_SIZE_BYTES
                + (hasLongVal ? Keccak256Helper.DEFAULT_SIZE_BYTES : lvalue)); //TODO check lvalue == 0 case

        buffer.put((byte) ARITY);

        byte flags = 0;

        if (this.isSecure) {
            flags |= 1;
        }

        if (hasLongVal) {
            flags |= 2;
        }

        buffer.put(flags);
        buffer.putShort((short) bits);
        buffer.putShort((short) lshared);

        if (lshared > 0) {
            buffer.put(encodedSharedPath);
        }

        for (int k = 0; k < ARITY; k++) {
            Keccak256 nodeHash = this.getHash(k);

            if (nodeHash == null) {
                continue;
            }
            try {
                buffer.put(nodeHash.getBytes());
            } catch (Exception e) {
                System.out.println(e);
            }
        }

        if (lvalue > 0) {
            if (hasLongVal) {
                buffer.put(this.getValueHash());
            }
            else {
                buffer.put(this.getValue());
            }
        }

        return buffer.array();
    }

    /**
     * save saves the unsaved current trie and subnodes to their associated store
     *
     */
    @Override
    public void save() {
        if (this.saved) {
            return;
        }

        // Without store, nodes cannot be saved. Abort silently
        if (this.store==null) {
            return;
        }

        if (this.nodes != null) {
            for (TrieImpl node : this.nodes) {
                if (node != null) {
                    node.save();
                }
            }
        }

        this.store.save(this);
        this.saved = true;
    }
/*
    @Override
    public void commit() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void rollback() {
        throw new UnsupportedOperationException();
    }
*/
    @Override
    public void copyTo(TrieStore target) {
        if (target.retrieve(this.getHash().getBytes()) != null) {
            return;
        }

        for (int k = 0; k < ARITY; k++) {
            this.retrieveNode(k);
        }

        if (this.nodes != null) {
            for (TrieImpl node : this.nodes) {
                if (node != null) {
                    node.copyTo(target);
                }
            }
        }

        target.save(this);
    }

    private static byte[] concat(byte[]... arrays) {
        int length = Stream.of(arrays).mapToInt(array -> array.length).sum();
        byte[] result = new byte[length];
        int pos = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, pos, array.length);
            pos += array.length;
        }
        return result;
    }

    // key is the key with exactly collectKeyLen bytes.
    // in non-expanded form (binary)
    // special value Integer.MAX_VALUE means collect them all.

    private void collectKeys(Set<ByteArrayWrapper> set, ExpandedKey key,int collectKeyLen) {


        if ((collectKeyLen!=Integer.MAX_VALUE) && (key.length() >  collectKeyLen)) {
            return;
        }

        if (this.encodedSharedPath != null) {
            // sharedPath is decoded (only ones and zeros)
            if (this.sharedPathLength+ key.length() > collectKeyLen)
                return;

            byte[] sharedPath = PathEncoder.decode(this.encodedSharedPath, this.sharedPathLength);
            key = key.append(new ExpandedKey(sharedPath));
        }

        // if the count is exact, and there is no prefix, then add
        // and the there is some value
        if (valueLength!=0)
            if ((collectKeyLen==Integer.MAX_VALUE) || (key.length() == collectKeyLen)) {
              // convert bit string into byte[]
              set.add(new ByteArrayWrapper(PathEncoder.encode(key.getData())));
        }

        for (int k = 0; k < ARITY; k++) {
            Trie node = this.retrieveNode(k);

            if (node == null) {
                return;
            }
            // Now append to the key the zero/one
            ((TrieImpl) node).collectKeys(set, key.append((byte)k), collectKeyLen);
        }
    }

    @Override
    // Special value Integer.MAX_VALUE means collect them all.
    public Set<ByteArrayWrapper> collectKeys(int byteSize) {
        Set<ByteArrayWrapper> set = new HashSet<>();

        int bitSize;
        if (byteSize==Integer.MAX_VALUE)
            bitSize =Integer.MAX_VALUE;
        else
            bitSize = byteSize*8;

        collectKeys(set,new ExpandedKey(), bitSize);
        return set;
    }

    @Override
    public Set<ByteArrayWrapper> collectKeysFrom(byte[] key) {
        Set<ByteArrayWrapper> set = new HashSet<>();
        ExpandedKey keyBytes = ExpandedKey.expandKey(key);
        TrieImpl parent = find(keyBytes, keyBytes.length(), 0);
        if (parent!=null)
            parent.collectKeys(set,keyBytes,Integer.MAX_VALUE);
        return set;
    }
    /**
     * trieSize returns the number of nodes in trie
     *
     * @return the number of tries nodes, includes the current one
     */
    @Override
    public int trieSize() {
        int size = 1;

        for (int k = 0; k < ARITY; k++) {
            Trie node = this.retrieveNode(k);

            if (node != null) {
                size += node.trieSize();
            }
        }

        return size;
    }

    /**
     * get retrieves the associated value given the key
     *
     * @param key   full key
     * @param length key total length
     * @param keyPosition  position of key being examined/added
     *
     * @return the associated value, null if the key is not found
     *
     */

    @Nullable
    private byte[] get(ExpandedKey key, int length, int keyPosition) {
        TrieImpl node = find(key,length,keyPosition);
        if (node==null) return null;
        return node.getValue();
    }

    @Nullable
    public Trie find(byte[] key) {
        ExpandedKey keyBytes = ExpandedKey.expandKey(key);
        TrieImpl node = find(keyBytes, keyBytes.length(), 0);
        return node;
    }

    @Nullable
    public boolean hasDataWithPrefix(byte[] key) {
        ExpandedKey keyBytes = ExpandedKey.expandKey(key);
        boolean result = hasDataWithPrefix(keyBytes, keyBytes.length(), 0);
        return result;
    }

    @Nullable
    private boolean hasDataWithPrefix(ExpandedKey key, int length, int keyPosition) {
        int position = keyPosition;

        if (position >= length) {
            return true;
        }

        if (this.encodedSharedPath != null) {
            byte[] sharedPath = PathEncoder.decode(this.encodedSharedPath, this.sharedPathLength);

            for (int k = 0; k < sharedPath.length; k++, position++) {
                if (position == length) {
                    return true;
                }

                if (key.get(position) != sharedPath[k]) {
                    return false;
                }
            }
        }

        Trie node = this.retrieveNode(key.get(position));

        // No child ?
        if (node == null) {
            return false;
        }

        return hasDataWithPrefix(key, length, position + 1);
    }

    @Nullable
    private TrieImpl find(ExpandedKey key, int length, int keyPosition) {
        int position = keyPosition;

        if (position >= length) {
            return this;
        }

        if (this.encodedSharedPath != null) {
            byte[] sharedPath = PathEncoder.decode(this.encodedSharedPath, this.sharedPathLength);

            for (int k = 0; k < sharedPath.length; k++, position++) {
                if (position >= length) {
                    return null;
                }

                if (key.get(position) != sharedPath[k]) {
                    return null;
                }
            }

            if (position >= length) {
                return this;
            }
        }

        Trie node = this.retrieveNode(key.get(position));

        if (node == null) {
            return null;
        }

        return ((TrieImpl)node).find(key, length, position + 1);
    }

    @Nullable
    private Pair<TrieImpl,Integer> findParent(TrieImpl parent,int parentValueAtPosition,
                                              ExpandedKey key, int length, int keyPosition) {
        int position = keyPosition;

        if (position >= length) {
            return (new Pair<>(parent,new Integer(parentValueAtPosition)));
        }

        if (this.encodedSharedPath != null) {
            byte[] sharedPath = PathEncoder.decode(this.encodedSharedPath, this.sharedPathLength);

            for (int k = 0; k < sharedPath.length; k++, position++) {
                if (position >= length) {
                    return null;
                }

                if (key.get(position) != sharedPath[k]) {
                    return null;
                }
            }

            if (position >= length) {
                return null;
            }
        }

        byte valueAtPosition = key.get(position);
        Trie node = this.retrieveNode(valueAtPosition );

        if (node == null) {
            return null;
        }

        return ((TrieImpl)node).findParent(this,valueAtPosition,key, length, position + 1);
    }
    /**
     * getNodeCount the number of direct subnodes in this node
     *
     * @return the number of direct subnodes in this node
     *
     * Takes into account that a node could be not present as an object and
     * only be referenced via its unique hash
     */
    protected int getNodeCount() {
        int count = 0;

        for (int k = 0; k < ARITY; k++) {
            TrieImpl node = this.getNode(k);
            Keccak256 localHash = this.getHash(k);

            if (node != null && !isEmptyTrie(node.valueLength, node.nodes, node.hashes) || localHash != null) {
                count++;
            }
        }

        return count;
    }

    /**
     * retrieveNode get the subnode at position n. If it is not present but its hash is known,
     * the node is retrieved from the store
     *
     * @param n position of subnode (0 to arity - 1)
     *
     * @return  the node or null if no subnode at position
     */
    protected Trie retrieveNode(int n) {
        Trie node = this.getNode(n);

        if (node != null) {
            return node;
        }

        if (this.hashes == null) {
            return null;
        }

        Keccak256 localHash = this.hashes[n];

        if (localHash == null) {
            return null;
        }

        node = this.store.retrieve(localHash.getBytes());

        if (node == null) {
            String strHash = localHash.toHexString();
            logger.error(ERROR_NON_EXISTENT_TRIE_LOGGER, strHash);
            panicProcessor.panic(PANIC_TOPIC, ERROR_NON_EXISTENT_TRIE + " " + strHash);
            throw new TrieSerializationException(ERROR_NON_EXISTENT_TRIE + " " + strHash, null);
        }

        if (this.nodes == null) {
            this.nodes = new TrieImpl[ARITY];
        }

        this.nodes[n] = (TrieImpl)node;

        return node;
    }

    /**
     * getHash get hash associated to subnode at positin n. If the hash is known
     * because it is in the internal hash cache, no access to subnode is needed.
     *
     * @param n     subnode position
     *
     * @return  node hash or null if no node is present
     */
    @Nullable
    protected Keccak256 getHash(int n) {
        if (this.hashes != null && this.hashes[n] != null) {
            return this.hashes[n];
        }

        if (this.nodes == null || this.nodes[n] == null) {
            return null;
        }

        TrieImpl node = this.nodes[n];

        if (isEmptyTrie(node.valueLength, node.nodes, node.hashes)) {
            return null;
        }

        Keccak256 localHash = node.getHash();

        this.setHash(n, localHash);

        return localHash;
    }

    /**
     * setHash save subnode hash at position n, in order to keep an internal cache
     *
     * @param n     the subnode position (0 to arity - 1)
     * @param hash  the subnode hash
     */
    private void setHash(int n, Keccak256 hash) {
        if (this.hashes == null) {
            this.hashes = new Keccak256[ARITY];
        }

        this.hashes[n] = hash;
    }

    /**
     * serialize returns the full trie data (this node and its subnodes)
     * in a byte array
     *
     * @return full trie serialized as byte array
     */
    public byte[] serialize() {
        this.save();

        byte[] bytes = this.store.serialize();
        byte[] root = this.getHash().getBytes();

        ByteBuffer buffer = ByteBuffer.allocate(Short.BYTES + Keccak256Helper.DEFAULT_SIZE_BYTES + bytes.length);

        buffer.putShort((short) 0);
        buffer.put(root);
        buffer.put(bytes);

        return buffer.array();
    }

    /**
     * deserialize returns a NewTrieImpl, from its serialized bytes
     *
     * @return full trie deserialized from byte array
     */
    public static Trie deserialize(byte[] bytes) {
        ByteArrayInputStream bstream = new ByteArrayInputStream(bytes);
        DataInputStream dstream = new DataInputStream(bstream);

        try {
            dstream.readShort();

            byte[] root = new byte[Keccak256Helper.DEFAULT_SIZE_BYTES];

            if (dstream.read(root) != Keccak256Helper.DEFAULT_SIZE_BYTES) {
                throw new EOFException();
            }

            TrieStoreImpl store = TrieStoreImpl.deserialize(bytes, Short.BYTES + Keccak256Helper.DEFAULT_SIZE_BYTES, bytes.length - Short.BYTES - Keccak256Helper.DEFAULT_SIZE_BYTES, new HashMapDB());

            Trie newTrie = store.retrieve(root);

            if (newTrie == null) {
                String strHash = Hex.toHexString(root);
                logger.error(ERROR_NON_EXISTENT_TRIE_LOGGER, strHash);
                panicProcessor.panic(PANIC_TOPIC, ERROR_CREATING_TRIE + " " + strHash);
                throw new TrieSerializationException(ERROR_CREATING_TRIE + " " + strHash, null);
            }

            return newTrie;
        }
        catch (IOException ex) {
            logger.error(ERROR_CREATING_TRIE, ex);
            panicProcessor.panic(PANIC_TOPIC, ERROR_CREATING_TRIE +": " + ex.getMessage());
            throw new TrieSerializationException(ERROR_CREATING_TRIE, ex);
        }
    }

    /**
     * getNode gets the subnode at position n
     *
     * @param n
     * @return
     */
    private TrieImpl getNode(int n) {
        if (this.nodes == null) {
            return null;
        }

        return this.nodes[n];
    }

    /**
     * put key with associated value, returning a new NewTrie
     *
     * @param key   key to be updated
     * @param length    total length of key
     * @param keyPosition  current position of the key to be processed
     * @param value     associated value
     *
     * @return the new NewTrie containing the tree with the new key value association
     *
     */
    private TrieImpl put(ExpandedKey key, int length, int keyPosition, byte[] value) {
        // First of all, setting the value as an empty byte array is equivalent
        // to removing the key/value. This is because other parts of the trie make
        // this equivalent. Use always null to mark a node for deletion.
        if ((value!=null) && (value.length==0))
            value =null;
        TrieImpl trie = this.internalPut(key, length, keyPosition, value);

        // the following code coalesces nodes if needed for delete operation

        // it's null or it is not a delete operation
        if (trie == null || value != null) {
            return trie;
        }

        if (isEmptyTrie(trie.valueLength, trie.nodes, trie.hashes)) {
            return null;
        }

        // only coalesce if node has only one child and no value
        if ((trie.valueLength != 0) || (trie.getNodeCount() !=1)) {
            return trie;
        }

        TrieImpl firstChild = null;
        int firstChildPosition = 0;

        for (int k = 0; firstChild == null && k < ARITY; k++) {
            firstChildPosition = k;
            firstChild = (TrieImpl)trie.retrieveNode(k);
        }

        if (firstChild == null) {
            throw new NullPointerException();
        }

        byte[] trieSharedPath;
        byte[] positionPath = new byte[] { (byte) firstChildPosition };

        if (trie.sharedPathLength == 0) {
            trieSharedPath = positionPath;
        }
        else {
            trieSharedPath = ByteUtils.concatenate(PathEncoder.decode(trie.encodedSharedPath, trie.sharedPathLength), positionPath);
        }

        byte[] newSharedPath;

        if (firstChild.sharedPathLength == 0) {
            newSharedPath = trieSharedPath;
        }
        else {
            byte[] childSharedPath = PathEncoder.decode(firstChild.encodedSharedPath, firstChild.sharedPathLength);
            newSharedPath = ByteUtils.concatenate(trieSharedPath, childSharedPath);
        }

        TrieImpl newTrie = (TrieImpl)firstChild.cloneTrie();
        newTrie.sharedPathLength = newSharedPath.length;
        newTrie.encodedSharedPath = PathEncoder.encode(newSharedPath);

        return newTrie;
    }

    private static int getDataLength(byte[] value) {
        if (value==null)
            return 0;
        return value.length;
    }

    private TrieImpl internalPut(ExpandedKey key, int length, int keyPosition, byte[] value) {
        int position = keyPosition;

        if (this.encodedSharedPath != null) {
            byte[] sharedPath = PathEncoder.decode(this.encodedSharedPath, this.sharedPathLength);

            int k = lengthOfCommonPath(key, length, keyPosition, sharedPath);

            if (k >= sharedPath.length) {
                position += sharedPath.length;
            }
            else {
                return this.split(k).put(key, length, position, value);
            }
        }

        if (position >= length) {
            // To compare values we need to retrieve the previous value
            // if not already done so. We could also compare by hash, to avoid retrieval
            // We do a small optimization here: if sizes are not equal, then values
            // obviously are not.
            if (this.valueLength == getDataLength(value)) {
                if (Arrays.equals(this.getValue(), value)) {
                    return this;
                }
            }

            TrieImpl[] newNodes = cloneNodes(false);
            Keccak256[] newHashes = cloneHashes();

            if (isEmptyTrie(getDataLength(value), newNodes, newHashes)) {
                return null;
            }

            return new TrieImpl(this.encodedSharedPath, this.sharedPathLength,
                    value, newNodes, newHashes, this.store,
                    getDataLength(value),null).withSecure(this.isSecure);
        }

        if (isEmptyTrie(this.valueLength, this.nodes, this.hashes)) {
            int lshared = length - position;
            byte[] shared = new byte[lshared];
            key.copy(position,shared, 0, lshared);
            return new TrieImpl(this.store, PathEncoder.encode(shared), lshared, value, this.isSecure,getDataLength(value),null);
        }

        TrieImpl[] newNodes = cloneNodes(true);
        Keccak256[] newHashes = cloneHashes();

        int pos = key.get(position);

        TrieImpl node = (TrieImpl)retrieveNode(pos);

        if (node == null) {
            node = new TrieImpl(this.store, this.isSecure);
        }

        TrieImpl newNode = node.put(key, length, position + 1, value);

        // reference equality
        if (newNode == node) {
            return this;
        }

        newNodes[pos] = newNode;

        if (newHashes != null) {
            newHashes[pos] = null;
        }

        if (isEmptyTrie(this.valueLength, newNodes, newHashes)) {
            return null;
        }

        return new TrieImpl(this.encodedSharedPath, this.sharedPathLength, this.value, newNodes, newHashes, this.store,this.valueLength,this.valueHash).withSecure(this.isSecure);
    }

    private int lengthOfCommonPath(ExpandedKey key, int length, int position, byte[] sharedPath) {
        int k;

        for (k = 0; k < sharedPath.length && position + k < length; k++) {
            if (sharedPath[k] != key.get(position + k)) {
                break;
            }
        }

        return k;
    }

    private TrieImpl split(int nshared) {
        TrieImpl[] newChildNodes = this.cloneNodes(false);
        Keccak256[] newChildHashes = this.cloneHashes();

        TrieImpl newChildTrie = new TrieImpl(null, 0, this.value, newChildNodes, newChildHashes, this.store,this.valueLength,this.valueHash).withSecure(this.isSecure);

        byte[] sharedPath = PathEncoder.decode(this.encodedSharedPath, this.sharedPathLength);

        if (sharedPath.length > nshared + 1) {
            int newSharedLength = sharedPath.length - nshared - 1;
            byte[] newShared = new byte[newSharedLength];
            System.arraycopy(sharedPath, nshared + 1, newShared, 0, newSharedLength);
            newChildTrie.encodedSharedPath = PathEncoder.encode(newShared);
            newChildTrie.sharedPathLength = newSharedLength;
        }

        TrieImpl newTrie = new TrieImpl(this.store, this.isSecure);
        TrieImpl[] newNodes = new TrieImpl[ARITY];
        int pos = sharedPath[nshared];
        newNodes[pos] = newChildTrie;
        newTrie.nodes = newNodes;

        if (nshared > 0) {
            byte[] newSharedPath = new byte[nshared];
            System.arraycopy(sharedPath, 0, newSharedPath, 0, nshared);
            newTrie.encodedSharedPath = PathEncoder.encode(newSharedPath);
            newTrie.sharedPathLength = nshared;
        }

        return newTrie;
    }

    /**
     * cloneHashes clone the internal subnode hashes cache
     *
     * @return a copy of the original hashes
     */
    @Nullable
    private Keccak256[] cloneHashes() {
        if (this.hashes == null) {
            return null;
        }

        int nhashes = this.hashes.length;
        Keccak256[] newHashes = new Keccak256[nhashes];

        for (int k = 0; k < nhashes; k++) {
            newHashes[k] = this.hashes[k];
        }

        return newHashes;
    }

    /**
     * cloneNodes clone the current list of nodes
     *
     * @param create    create an empty list if the current list is null
     *
     * @return the new list of nodes
     */
    @Nullable
    private TrieImpl[] cloneNodes(boolean create) {
        if (nodes == null && !create) {
            return null;
        }

        TrieImpl[] newnodes = new TrieImpl[ARITY];

        if (nodes != null) {
            for (int k = 0; k < ARITY; k++) {
                newnodes[k] = nodes[k];
            }
        }

        return newnodes;
    }

    @Override
    public boolean hasStore() {
        return this.store != null;
    }

    /**
     * isEmptyTrie checks the existence of subnodes, subnodes hashes or value
     *
     * @param valueLength     length of current value
     * @param nodes     list of subnodes
     * @param hashes    list of subnodes hashes
     *
     * @return true if no data
     */
    private static boolean isEmptyTrie(int valueLength, TrieImpl[] nodes, Keccak256[] hashes) {
        if (valueLength != 0) {
            return false;
        }

        if (nodes != null) {
            for (int k = 0; k < nodes.length; k++) {
                if (nodes[k] != null) {
                    return false;
                }
            }
        }

        if (hashes != null) {
            for (int k = 0; k < hashes.length; k++) {
                if (hashes[k] != null) {
                    return false;
                }
            }
        }

        return true;
    }

    public static byte[] expandKey(byte[] bytes) {
        int factor = 8;
        int mask = 0x01;
        int nbits = 1;

        byte[] keyBytes = new byte[bytes.length * factor];
        int l = bytes.length;
        int j = 0;

        for (int k = 0; k < l; k++) {
            byte b = bytes[k];

            for (int i = 0; i < factor; i++) {
                keyBytes[j++] = (byte) ((b >> (nbits * (factor - i - 1))) & mask);
            }
        }

        return keyBytes;
    }

    public Trie getSnapshotTo(Keccak256 hash) {
        // This call shouldn't be needed since internally try can know it should store data
        //this.save();

        if (emptyHash.equals(hash)) {
            return new TrieImpl(this.store, this.isSecure);
        }

        Trie newTrie = this.store.retrieve(hash.getBytes());

        if (newTrie == null) {
            String strHash = hash.toHexString();
            logger.error(ERROR_NON_EXISTENT_TRIE_LOGGER, strHash);
            panicProcessor.panic(PANIC_TOPIC, ERROR_CREATING_TRIE + " " + strHash);

            throw new TrieSerializationException(ERROR_CREATING_TRIE + " " + strHash, null);
        }

        return newTrie;
    }

    public TrieStore getStore() {
        return this.store;
    }

    public boolean hasLongValue() {
        return this.valueLength > 32;
    }

    public int getValueLength() {
        return this.valueLength;
    }

    // Now getValueHash() returns the hash of the value independently
    // on it's size: use hasLongValue() to known what type of value it will store in
    // the node.
    public byte[] getValueHash() {
        if (valueHash==null) {
            if (this.valueLength != 0) {
                valueHash = Keccak256Helper.keccak256(this.value);
            }
            // For empty values (valueLength==0) we return the null hash because
            // in this trie empty arrays cannot be stored.
        }
        return valueHash;
    }

    @Override
    public Iterator<IterationElement> getInOrderIterator() {
        return new InOrderIterator(new byte[]{}, this);
    }

    @Override
    public Iterator<IterationElement> getPreOrderIterator() {
        return new PreOrderIterator(new byte[]{}, this);
    }

    @Override
    public Iterator<IterationElement> getPostOrderIterator() {
        return new PostOrderIterator(new byte[]{}, this);
    }

    protected byte[] retrieveLongValue() {
        return store.retrieveValue(valueHash);
    }

    protected void checkValueLengthAfterRetrieve() {
        // At this time value==null and value.length!=null is really bad.
        if ((value==null) && (valueLength != 0))
            // Serious DB inconsistency here
            throw new IllegalArgumentException(INVALID_VALUE_LENGTH);

        checkValueLength();

    }

    protected void checkValueLength() {
        if ((value!=null) && (value.length != valueLength))
            // Serious DB inconsistency here
            throw new IllegalArgumentException(INVALID_VALUE_LENGTH);

        if ((value==null) && (valueLength != 0) && ((valueHash==null) || (valueHash.length==0)))
            // Serious DB inconsistency here
            throw new IllegalArgumentException(INVALID_VALUE_LENGTH);
    }

    public byte[] getValue() {
        if ((valueLength!=0) && (value==null)) {
            this.value = retrieveLongValue();
            checkValueLengthAfterRetrieve();
        }
        return this.value;
    }

    protected static int getEncodedPathLength(int length) {
        return length / 8 + (length % 8 == 0 ? 0 : 1);
    }

    /**
     * makeEmpyHash creates the hash associated to empty nodes
     *
     * @return a hash with zeroed bytes
     */
    private static Keccak256 makeEmptyHash() {
        return new Keccak256(Keccak256Helper.keccak256(RLP.encodeElement(EMPTY_BYTE_ARRAY)));
    }

    @Override
    public byte[] getEncodedSharedPath() {
        return encodedSharedPath;
    }

    @Override
    public int getSharedPathLength() {
        return sharedPathLength;
    }

    private static class ExpandedKey {
        private byte[] expandedKey;

        private ExpandedKey(byte[] aExpandedKey) {
            expandedKey = aExpandedKey;
        }

        private ExpandedKey() {
            expandedKey = new byte[]{};
        }

        public int length() {
            return expandedKey.length;
        }

        public byte get(int i) {
            return expandedKey[i];
        }

        public void copy(int srcPos, byte[] dest, int destPos, int length) {
            System.arraycopy(expandedKey, srcPos, dest, destPos, length);
        }

        public byte[] getData() {
            return expandedKey;
        }

        private static byte[] concat(byte[] first, byte[] second) {
            byte[] result = Arrays.copyOf(first, first.length + second.length);
            System.arraycopy(second, 0, result, first.length, second.length);
            return result;
        }

        public ExpandedKey append(byte k) {
            return new ExpandedKey(concat(expandedKey, new byte[]{k}));
        }

        public ExpandedKey append(ExpandedKey otherKey) {
            return new ExpandedKey(concat(expandedKey, otherKey.getData()));
        }

        /**
         * bytesToExpandedKey expand key to bytes according to node arity
         * Example: if arity is 16 (16 subnodes per node) each key byte is expanded to
         * two bytes, representing two nibbles
         * if arity is 2 (binary trie) each original byte is expanded 8 bytes, each representing
         * a bit value of the original byte
         *
         * @param bytes original key
         * @return expanded key
         */
        private static ExpandedKey expandKey(byte[] bytes) {
            return new ExpandedKey(TrieImpl.expandKey(bytes));
        }
    }

    /**
     * Returns the leftmost node that has not yet been visited that node is normally on top of the stack
     */
    private static class InOrderIterator implements Iterator<IterationElement> {

        private final Deque<IterationElement> visiting;

        public InOrderIterator(byte[] traversedPath, TrieImpl root) {
            Objects.requireNonNull(root);
            this.visiting = new LinkedList<>();
            // find the leftmost node, pushing all the intermediate nodes onto the visiting stack
            pushLeftmostNode(traversedPath, root);
            // now the leftmost unvisited node is on top of the visiting stack
        }

        /**
         * return the leftmost node that has not yet been visited that node is normally on top of the stack
         */
        @Override
        public IterationElement next() {
            IterationElement visitingElement = visiting.pop();
            TrieImpl node = (TrieImpl) visitingElement.getNode();
            // if the node has a right child, its leftmost node is next
            Trie rightNode = node.retrieveNode(1);
            if (rightNode != null) {
                pushLeftmostNode( // find the leftmost node of the right child
                    concatKeys(visitingElement.getTraversedPath(), node, (byte) 0x01),
                    (TrieImpl) rightNode
                );
                // note "node" has been replaced on the stack by its right child
            } // else: no right subtree, go back up the stack
            // next node on stack will be next returned
            return visitingElement;
        }

        @Override
        public boolean hasNext() {
            return !visiting.isEmpty(); // no next node left
        }

        /**
         * Find the leftmost node from this root, pushing all the intermediate nodes onto the visiting stack
         *
         * @param traversedPath
         * @param node the root of the subtree for which we are trying to reach the leftmost node
         */
        private void pushLeftmostNode(byte[] traversedPath, TrieImpl node) {
            // find the leftmost node
            if (node != null) {
                visiting.push(new IterationElement(traversedPath, node)); // push this node
                pushLeftmostNode( // recurse on next left node
                        concatKeys(traversedPath, node, (byte) 0x00),
                        (TrieImpl) node.retrieveNode(0)
                );
            }
        }
    }

    private class PreOrderIterator implements Iterator<IterationElement> {

        private final Deque<IterationElement> visiting;

        public PreOrderIterator(byte[] traversedPath, TrieImpl trie) {
            Objects.requireNonNull(trie);
            this.visiting = new LinkedList<>();
            this.visiting.push(new IterationElement(traversedPath, trie));
        }

        @Override
        public IterationElement next() {
            IterationElement visitingElement = visiting.pop();
            TrieImpl node = (TrieImpl) visitingElement.getNode();
            // need to visit the left subtree first, then the right since a stack is a LIFO, push the right subtree first,
            // then the left
            TrieImpl rightNode = (TrieImpl) node.retrieveNode(1);
            if (rightNode != null) {
                visiting.push(new IterationElement(concatKeys(visitingElement.getTraversedPath(), node, (byte) 0x01), rightNode));
            }
            TrieImpl leftNode = (TrieImpl) node.retrieveNode(0);
            if (leftNode != null) {
                visiting.push(new IterationElement(concatKeys(visitingElement.getTraversedPath(), node, (byte) 0x00), leftNode));
            }
            // may not have pushed anything.  If so, we are at the end
            return visitingElement;
        }

        @Override
        public boolean hasNext() {
            return !visiting.isEmpty(); // no next node left
        }
    }

    private class PostOrderIterator implements Iterator<IterationElement> {

        private final Deque<IterationElement> visiting;
        private final Deque<Boolean> visitingRightChild;

        public PostOrderIterator(byte[] traversedPath, TrieImpl trie) {
            Objects.requireNonNull(trie);
            this.visiting = new LinkedList<>();
            this.visitingRightChild = new LinkedList<>();
            // find the leftmost node, pushing all the intermediate nodes onto the visiting stack
            pushLeftmostNodeRecord(traversedPath, trie);
            // the node on top of the visiting stack is the next one to be visited, unless it has a right subtree
        }

        @Override
        public boolean hasNext() {
            return !visiting.isEmpty(); // no next node left
        }

        @Override
        public IterationElement next() {
            IterationElement visitingElement = visiting.peek();
            TrieImpl node = (TrieImpl) visitingElement.getNode();
            Trie rightNode = node.retrieveNode(1);
            if (rightNode == null || visitingRightChild.peek()) { // no right subtree, or right subtree already visited
                // already visited right child, time to visit the node on top
                visiting.removeFirst(); // it was already picked
                visitingRightChild.removeFirst(); // it was already picked
                return visitingElement;
            } else { // now visit this node's right subtree
                visitingRightChild.removeFirst();
                visitingRightChild.push(Boolean.TRUE);
                pushLeftmostNodeRecord( // now push everything down to the leftmost node in the right subtree
                        concatKeys(visitingElement.getTraversedPath(), node, (byte) 0x01),
                        (TrieImpl) rightNode
                );
                return next(); // use recursive call to visit that node
            }
        }

        /**
         * Find the leftmost node from this root, pushing all the intermediate nodes onto the visiting stack
         * and also stating that each is a left child of its parent
         * @param traversedPath
         * @param node the root of the subtree for which we are trying to reach the leftmost node
         */
        private void pushLeftmostNodeRecord(byte[] traversedPath, TrieImpl node) {
            // find the leftmost node
            if (node != null) {
                visiting.push(new IterationElement(traversedPath, node)); // push this node
                visitingRightChild.push(Boolean.FALSE); // record that it is on the left
                Trie leftNode = node.retrieveNode(0);
                pushLeftmostNodeRecord(concatKeys(traversedPath, node, (byte) 0x00), (TrieImpl) leftNode); // continue looping
            }
        }
    }

    private static byte[] concatKeys(byte[] traversedPath, TrieImpl node, byte childSuffix) {
        if (node.encodedSharedPath != null) {
            byte[] sharedPath = PathEncoder.decode(node.encodedSharedPath, node.sharedPathLength);
            traversedPath = concat(traversedPath, sharedPath);
        }
        return concat(traversedPath, new byte[] { childSuffix });
    }
}
