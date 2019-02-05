package co.rsk.trie;

import co.rsk.core.RskAddress;
import co.rsk.crypto.Keccak256;
import org.ethereum.core.AccountState;
import org.ethereum.crypto.HashUtil;
import org.ethereum.crypto.Keccak256Helper;
import org.ethereum.db.MutableRepository;

import java.util.Arrays;
import java.util.stream.Stream;

public class TrieConverter {

    private static final byte LEFT_CHILD_IMPLICIT_KEY = (byte) 0x00;
    private static final byte RIGHT_CHILD_IMPLICIT_KEY = (byte) 0x01;

    public byte[] getOrchidAccountTrieRoot(TrieImpl src) {
        return getOrchidAccountTrieRoot(new byte[]{}, src, true);
    }

    private byte[] getOrchidAccountTrieRoot(byte[] key, TrieImpl src, boolean removeFirst8bits) {
        if (src == null) {
            return HashUtil.EMPTY_TRIE_HASH;
        }

        // shared Path
        byte[] encodedSharedPath = src.getEncodedSharedPath();
        int sharedPathLength = src.getSharedPathLength();
        if (encodedSharedPath != null) {
            byte[] sharedPath = PathEncoder.decode(encodedSharedPath, sharedPathLength);
            key = concat(key, sharedPath);
        }
        if (removeFirst8bits) {
            if (sharedPathLength < 8) {
                throw new IllegalStateException("Unable to remove first 8-bits if path length is less than 8");
            }
            sharedPathLength -= 8;
            encodedSharedPath = Arrays.copyOfRange(encodedSharedPath,1, encodedSharedPath.length);
        }
        TrieImpl child0 = (TrieImpl) src.retrieveNode(0);
        byte[] child0Hash = null;
        TrieImpl child1 = (TrieImpl) src.retrieveNode(1);
        byte[] child1Hash = null;

        if (key.length == (1 + MutableRepository.SECURE_KEY_SIZE + RskAddress.LENGTH_IN_BYTES) * Byte.SIZE) {
            // We've reached the Account level. From now on everything will be different.
            AccountState astate = new AccountState(src.getValue());
            OldAccountState oldState = new OldAccountState(astate.getNonce(),astate.getBalance());
            // child1 (0x80) will be the code
            if (child1 != null) {
                oldState.setCodeHash(child1.getValueHash());
            }
            // the child0 side will be the storage. The first child corresponds to the
            // 8-bit zero prefix. 1 bit is consumed by the branch. 7-bits left. We check that
            if (child0 != null) {
                if (child0.getSharedPathLength()!=7) {
                    throw new IllegalStateException("First child must be 7-bits length");
                }
                // We'll create an ad-hoc trie for storage cells, the first
                // child0's child is the root of this try. What if it has two children?
                // This can happen if there are two hashed storage keys, one begining with
                // 0 and another with 1.
                byte[] stateRoot = getOrchidStateRoot(child0);
                oldState.setStateRoot(stateRoot);
            }

            byte[] avalue = oldState.getEncoded();
            byte[] orchidKey = extractOrchidAccountKeyPathFromUnitrieKey(key, sharedPathLength);
            encodedSharedPath = PathEncoder.encode(orchidKey);
            sharedPathLength = orchidKey.length;
            TrieImpl newNode = new TrieImpl(
                    encodedSharedPath, sharedPathLength,
                    avalue, null, null, null,
                    avalue.length,null).withSecure(src.isSecure());///src.isSecure()

            return newNode.getHash().getBytes();
        }

        if (child0 != null) {
            child0Hash = getOrchidAccountTrieRoot(concat(key, LEFT_CHILD_IMPLICIT_KEY), child0, false);
        }

        if (child1 != null) {
            child1Hash = getOrchidAccountTrieRoot(concat(key, RIGHT_CHILD_IMPLICIT_KEY), child1, false);
        }

        Keccak256[] hashes = Stream.of(child0Hash, child1Hash).map(hash -> hash==null? null : new Keccak256(hash)).toArray(Keccak256[]::new);

        TrieImpl newNode = new TrieImpl(encodedSharedPath, sharedPathLength,
                src.getValue(), null, hashes, null, src.valueLength,
                src.getValueHash()).withSecure(src.isSecure());

        return newNode.getHash().getBytes();
    }

    private byte[] getOrchidStateRoot(TrieImpl unitrieStorageRoot) {
        return getOrchidStateRoot(new byte[] {}, unitrieStorageRoot, true, false, LEFT_CHILD_IMPLICIT_KEY);
    }

    private byte[] getOrchidStateRoot(byte[] key, TrieImpl unitrieStorageRoot, boolean removeFirstNodePrefix, boolean onlyChild, byte ancestor) {
        if (unitrieStorageRoot == null) {
            return HashUtil.EMPTY_TRIE_HASH;
        }

        // shared Path
        byte[] encodedSharedPath = unitrieStorageRoot.getEncodedSharedPath();
        int sharedPathLength = unitrieStorageRoot.getSharedPathLength();
        if (encodedSharedPath != null) {
            byte[] sharedPath = PathEncoder.decode(encodedSharedPath, sharedPathLength);
            key = concat(key, sharedPath);
        }

        TrieImpl child0 = (TrieImpl) unitrieStorageRoot.retrieveNode(0);
        TrieImpl child1 = (TrieImpl) unitrieStorageRoot.retrieveNode(1);
        byte[] child0Hash = null;
        if (child0 != null) {
            child0Hash = getOrchidStateRoot(concat(key, LEFT_CHILD_IMPLICIT_KEY), child0, false, removeFirstNodePrefix && child1 == null, LEFT_CHILD_IMPLICIT_KEY);
        }

        byte[] child1Hash = null;
        if (child1 != null) {
            child1Hash = getOrchidStateRoot(concat(key, RIGHT_CHILD_IMPLICIT_KEY), child1, false, removeFirstNodePrefix && child0 == null, RIGHT_CHILD_IMPLICIT_KEY);
        }

        Keccak256[] hashes = Stream.of(child0Hash, child1Hash).map(hash -> hash==null? null : new Keccak256(hash)).toArray(Keccak256[]::new);

        byte[] value = unitrieStorageRoot.getValue();
        int valueLength = unitrieStorageRoot.valueLength;
        byte[] valueHash = unitrieStorageRoot.getValueHash();

        if (removeFirstNodePrefix) {
            encodedSharedPath = null;
            sharedPathLength = 0;
            value = null; // also remove value
            valueLength = 0;
            valueHash = null;
            if (child0 != null && child1 == null) {
                return child0Hash;
            }
            if (child0 == null && child1 != null ) {
                return child1Hash;
            }
        }

        if (onlyChild) {
            byte[] expandedKey = PathEncoder.decode(encodedSharedPath, sharedPathLength);
            byte[] keyCopy = new byte[sharedPathLength + 1];
            System.arraycopy(expandedKey, 0, keyCopy, 1, sharedPathLength);
            keyCopy[0] = ancestor;
            encodedSharedPath = PathEncoder.encode(keyCopy);
            sharedPathLength++;
        }


        if ((hashes[0]==null) && (hashes[1]==null)) { // terminal node
            byte[] expandedSharedPath = extractOrchidStorageKeyPathFromUnitrieKey(key ,sharedPathLength);
            encodedSharedPath = PathEncoder.encode(expandedSharedPath);
            sharedPathLength = expandedSharedPath.length;
        }
        TrieImpl newNode = new TrieImpl(
                encodedSharedPath, sharedPathLength,
                value, null, hashes, null,
                valueLength,valueHash).withSecure(unitrieStorageRoot.isSecure());
        return newNode.getHash().getBytes();
    }

    private static byte[] concat(byte[] first, byte b) {
        return concat(first, new byte[]{b});
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    private byte[] extractOrchidAccountKeyPathFromUnitrieKey(byte[] key, int sharedPathLength) {
        byte[] unsecuredKey = Arrays.copyOfRange(key, key.length - RskAddress.LENGTH_IN_BYTES * Byte.SIZE, key.length);
        byte[] encodedKey = PathEncoder.encode(unsecuredKey);
        byte[] orchidTrieSecureKey = Keccak256Helper.keccak256(encodedKey);

        if (sharedPathLength < (MutableRepository.ACCOUNT_KEY_SIZE - MutableRepository.SECURE_KEY_SIZE) * Byte.SIZE) { // = 20 bytes = RskAddress.LENGTH_IN_BYTES
            throw new IllegalArgumentException("The unitrie doesn't share as much structure as we need to rebuild the Orchid trie");
        }

        byte[] expandedOrchidTrieSecureKey = PathEncoder.decode(orchidTrieSecureKey, Keccak256Helper.DEFAULT_SIZE);
        // the length of the structure that's shared between the Orchid trie and the Unitrie
        int commonTriePathLength  = MutableRepository.ACCOUNT_KEY_SIZE * Byte.SIZE - sharedPathLength;
        // the old key had 256 bits so the new node must contain what's needed to complete that information for an account
        int newPrefixSize = Keccak256Helper.DEFAULT_SIZE - commonTriePathLength;

        byte[] newDecodedPrefix = new byte[newPrefixSize];
        System.arraycopy(expandedOrchidTrieSecureKey, commonTriePathLength, newDecodedPrefix, 0, newPrefixSize);

        return newDecodedPrefix;
    }

    private byte[] extractOrchidStorageKeyPathFromUnitrieKey(byte[] key, int sharedPathLength) {
        byte[] unsecuredKey = Arrays.copyOfRange(key, key.length - 256, key.length);
        byte[] encodedKey = PathEncoder.encode(unsecuredKey);
        byte[] orchidTrieSecureKey = Keccak256Helper.keccak256(encodedKey);

        //(MutableRepository.STORAGE_KEY_SIZE - MutableRepository.SECURE_KEY_SIZE * 2 + MutableRepository.STORAGE_PREFIX.length )
        if (sharedPathLength < 256) { //TODO(diegoll) review 248 = SECURE_KEY_SIZE + RskAddress size + STORAGE_PREFIX + SECURE_KEY_SIZE
            throw new IllegalArgumentException("The unitrie storage doesn't share as much structure as we need to rebuild the Orchid trie");
        }

        byte[] expandedOrchidTrieSecureKey = PathEncoder.decode(orchidTrieSecureKey, Keccak256Helper.DEFAULT_SIZE);

        int consumedFrom80bitPrefix  = 42 * Byte.SIZE - sharedPathLength;
        int newPrefixSize  = sharedPathLength - 10 * Byte.SIZE;
        byte[] newDecodedPrefix = new byte[newPrefixSize];

        System.arraycopy(expandedOrchidTrieSecureKey, consumedFrom80bitPrefix, newDecodedPrefix, 0, newPrefixSize);

        return newDecodedPrefix;
    }

}
