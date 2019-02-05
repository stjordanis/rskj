package org.ethereum.db;

import co.rsk.core.Coin;
import co.rsk.core.RskAddress;
import co.rsk.crypto.Keccak256;
import co.rsk.db.*;
import co.rsk.trie.MutableSubtrie;
import co.rsk.trie.MutableTrie;
import co.rsk.trie.Trie;
import org.bouncycastle.util.encoders.Hex;
import org.ethereum.core.AccountState;
import org.ethereum.core.Block;
import org.ethereum.core.Repository;
import org.ethereum.crypto.HashUtil;
import org.ethereum.crypto.Keccak256Helper;
import org.ethereum.vm.DataWord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.util.*;
import java.util.stream.Stream;

public class MutableRepository implements Repository {

    // in bytes
    public static final int SECURE_KEY_SIZE = 10;
    // in bytes
    public static final int ACCOUNT_KEY_SIZE = SECURE_KEY_SIZE + RskAddress.LENGTH_IN_BYTES;
    public static final int STORAGE_KEY_SIZE = ACCOUNT_KEY_SIZE + Byte.BYTES + SECURE_KEY_SIZE + 32; //TODO(diegoll): add a constant to DataWord and use that instead of 32

    private static final Logger logger = LoggerFactory.getLogger("repository");

    private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];
    private static final byte[] ONE_BYTE_ARRAY = new byte[] { 0x01 };
    private static final byte[] DOMAIN_PREFIX = new byte[] { 0x00 };
    private static final byte[] CODE_PREFIX = new byte[] { (byte) 0x80 }; // This makes the MSB 1 be branching
    private static final byte[] STORAGE_PREFIX = new byte[] { 0x00 }; // This makes the MSB 0 be branching

    private MutableTrie trie;
    private boolean closed;

    public MutableRepository(Trie atrie) {
        this(new MutableTrieImpl(atrie));
    }

    public MutableRepository(MutableTrie mutableTrie) {
        this.trie = mutableTrie;
    }

    public MutableTrie getMutableTrie() {
        return trie;
    }

    @Override
    public synchronized AccountState createAccount(RskAddress addr) {
        AccountState accountState = new AccountState();
        updateAccountState(addr, accountState);
        return accountState;
    }

    @Override
    public synchronized void setupContract(RskAddress addr) {
        byte[] prefix = getAccountStoragePrefixKey(addr, trie.isSecure());
        this.trie.put(prefix, ONE_BYTE_ARRAY);
    }

    private byte[] getAccountData(RskAddress addr) {
        return this.trie.get(getAccountKey(addr));
    }

    // This is a performance enhancement. When multiple storage rows for the same
    // contract are stored, the same RskAddress is hashed over and over.
    // We don't need to re-hash it if was hashed last time.
    // The reduction we get is about 50% (2x efficiency)
    private RskAddress lastAddr;
    private byte[] lastAccountKey;

    synchronized private byte[] getAccountKey(RskAddress addr) {
        if (addr.equals(lastAddr)) {
            return lastAccountKey;
        }

        lastAccountKey = getAccountKey(addr, trie.isSecure());
        lastAddr = addr;
        return lastAccountKey;
    }

    private static byte[] getAccountKey(RskAddress addr, boolean isSecure) {
        byte[] secureKey;
        if (isSecure) {
            secureKey = Arrays.copyOfRange(Keccak256Helper.keccak256(addr.getBytes()), 0, SECURE_KEY_SIZE);
        } else {
            secureKey = new byte[]{};
        }
        return concat(DOMAIN_PREFIX, secureKey, addr.getBytes());
    }

    private byte[] getAccountKeyChildKey(RskAddress addr, byte[] child) {
        // try to use cache. not a static : return getAccountKeyChildKey(addr,child,trie.isSecure());
        return concat(getAccountKey(addr), child);
    }

    private static byte[] getAccountKeyChildKey(RskAddress addr, byte[] child, boolean isSecure) {
        return concat(getAccountKey(addr, isSecure), child);
    }

    @Override
    public synchronized boolean isExist(RskAddress addr) {
        // Here we assume size !=0 means the account exists
        return this.trie.getValueLength(getAccountKey(addr)) > 0;
    }

    @Override
    public synchronized AccountState getAccountState(RskAddress addr) {
        AccountState result = null;
        byte[] accountData = getAccountData(addr);

        // If there is no account it returns null
        if (accountData != null && accountData.length != 0) {
            result = new AccountState(accountData);
        }
        return result;
    }

    @Override
    public synchronized void delete(RskAddress addr) {
        this.trie.deleteRecursive(getAccountKey(addr));
    }

    @Override
    public synchronized void hibernate(RskAddress addr) {
        AccountState account = getAccountStateOrCreateNew(addr);

        account.hibernate();
        updateAccountState(addr, account);
    }

    @Override
    public void setNonce(RskAddress addr,BigInteger nonce) {
        AccountState account = getAccountStateOrCreateNew(addr);

        account.setNonce(nonce);
        updateAccountState(addr, account);
    }

    @Override
    public ContractDetails getContractDetails(RskAddress addr) {
        return createProxyContractDetails(addr);
    }

    @Override
    public synchronized BigInteger increaseNonce(RskAddress addr) {
        AccountState account = getAccountStateOrCreateNew(addr);

        account.incrementNonce();
        updateAccountState(addr, account);
        return account.getNonce();
    }

    @Override
    public synchronized BigInteger getNonce(RskAddress addr) {
        // Why would getNonce create an Account in the repository? The semantic of a get()
        // is clear: do not change anything!
        AccountState account = getAccountState(addr);
        if (account==null) {
            return BigInteger.ZERO;
        }
        return account.getNonce();
    }

    private synchronized ContractDetails createProxyContractDetails(RskAddress addr) {
        MutableSubtrie mst = new MutableSubtrie(trie,
                // Compute the prefix with isSecure transformation, because there is no
                // repository object to do it for us.
                MutableRepository.getAccountStoragePrefixKey(addr,trie.isSecure())
        );

        return new ProxyContractDetails(addr.getBytes(),
                mst,getCode(addr));
    }

    private byte[] getCodeKey(RskAddress addr) {
        return getAccountKeyChildKey(addr,CODE_PREFIX);
    }

    private static byte[] getAccountStoragePrefixKey(RskAddress addr, boolean isSecure) {
        return getAccountKeyChildKey(addr, STORAGE_PREFIX, isSecure);
    }

    // Use a cache
    private byte[] getAccountStoragePrefixKey(RskAddress addr) {
        return getAccountKeyChildKey(addr, STORAGE_PREFIX);
    }

    public static byte[] getStorageTailKey(byte[] subkey, boolean isSecure) {
        if (!isSecure) {
            return subkey;
        }
        byte[] secureKey = Arrays.copyOfRange(Keccak256Helper.keccak256(subkey), 0, SECURE_KEY_SIZE);
        return concat(secureKey, subkey);
    }

    private byte[] getAccountStorageKey(RskAddress addr, byte[] subkey) {
        byte[] secureSubKey = getStorageTailKey(subkey, trie.isSecure());
        return concat(getAccountStoragePrefixKey(addr), secureSubKey);
    }

    @Override
    public synchronized void saveCode(RskAddress addr, byte[] code) {
        byte[] key = getCodeKey(addr);
        this.trie.put(key,code);

        boolean accountExists = isExist(addr);
        if (code == null || code.length==0) {
            if (!accountExists) {
                return;
            }
        }

        if (!accountExists) {
            createAccount(addr);
        }
    }

    @Override
    public synchronized byte[] getCodeHash(RskAddress addr) {
        AccountState  account = getAccountState(addr);
        if (account == null || account.isHibernated()) {
            return null;
        }

        byte[] key = getCodeKey(addr);
        return this.trie.getValueHash(key);
    }

    @Override
    public synchronized int getCodeLength(RskAddress addr) {
        AccountState  account = getAccountState(addr);
        if (account == null || account.isHibernated()) {
            return 0;
        }

        byte[] key = getCodeKey(addr);
        return this.trie.getValueLength(key);
    }


    @Override
    public synchronized byte[] getCode(RskAddress addr) {
        if (!isExist(addr)) {
            return EMPTY_BYTE_ARRAY;
        }

        AccountState  account = getAccountState(addr);

        if (account.isHibernated()) {
            return EMPTY_BYTE_ARRAY;
        }
        byte[] key = getCodeKey(addr);
        return this.trie.get(key);
    }

    @Override
    public boolean isContract(RskAddress addr) {
        return getContractDetails(addr) != null;
    }


    @Override
    public synchronized void addStorageRow(RskAddress addr, DataWord key, DataWord value) {
        // This is important: DataWords are stored stripping leading zeros.
        addStorageBytes(addr,key,value.getByteArrayForStorage());
    }

    @Override
    public byte[] getStorageStateRoot(RskAddress addr) {
        byte[] prefix = getAccountStoragePrefixKey(addr,trie.isSecure());

        // The value should be ONE_BYTE_ARRAY, but we don't need to check
        // nothing else could be there. right?
        Trie storageRootNode = this.trie.getTrie().find(prefix);
        if (storageRootNode == null) {
            return HashUtil.EMPTY_TRIE_HASH;
        }

        // Now it's a bit tricky what to return: if I return the storageRootNode hash
        // then it's counting the "0x01" value, so the try one gets will never match the
        // trie one gets if creating the trie without any other data. Unless the PDV trie
        // is used. The best we can do is to return storageRootNode  hash
        return storageRootNode.getHash().getBytes();
    }

    @Override
    public boolean contractHasStorage(RskAddress addr) {
        // Having a storage root node allows us to do it simpler than this:
        // byte[] triekey = getAccountKey(addr);
        // return this.trie.getTrie().hasDataWithPrefix(triekey);
        // We can just ask for the state root node.
        byte[] prefix = getAccountStoragePrefixKey(addr,trie.isSecure());

        // The value should be ONE_BYTE_ARRAY, but we don't need to check
        // nothing else could be there. right?
        return this.trie.get(prefix) != null;


    }

    @Override
    public synchronized void addStorageBytes(RskAddress addr, DataWord key, byte[] value) {
        // This should not happen in production because contracts are created
        // before storage cells are added to them.
        // But it happens in Repository tests, that create only storage row cells.
        if (!isExist(addr)) {
            createAccount(addr);
            setupContract(addr);
        }

        byte[] triekey = getAccountStorageKey(addr,key.getData());

        GlobalKeyMap.addStorageKey(triekey,key);

        // Special case: if the value is an empty vector, we pass "null" which
        // commands the trie to remove the item. Note that if the call comes
        // from addStorageRow(), this method will already have replaced 0 by null,
        // so the conversion here only applies if this is called directly.
        // If suppose this only occurs in tests, but it can also occur in precompiled
        // contracts that store data directly using this method.
        if (value == null || value.length == 0) {
            this.trie.put(triekey, null);
        } else {
            this.trie.put(triekey, value);
        }
    }

    // Returns null if the key doesn't exist
    @Override
    public synchronized DataWord getStorageValue(RskAddress addr, DataWord key) {
        byte[] triekey = getAccountStorageKey(addr,key.getData());
        byte[] value = this.trie.get(triekey);
        if (value == null) {
            return null;
        }

        DataWord dw = new DataWord();
        dw.assignData(value);
        // Creates a new copy to prevent external modification of cached values
        return dw;
    }

    @Override
    public synchronized byte[] getStorageBytes(RskAddress addr, DataWord key) {
        byte[] triekey = getAccountStorageKey(addr,key.getData());
        return this.trie.get(triekey);
    }

    @Override
    public Iterator<DataWord> getStorageKeys(RskAddress addr) {
        return getContractDetails(addr).getStorageKeys().iterator();
    }

    @Override
    public int getStorageKeysCount(RskAddress addr) {
        return getContractDetails(addr).getStorageKeys().size();
    }

    @Override
    public synchronized Coin getBalance(RskAddress addr) {
        AccountState account = getAccountState(addr);
        //return (account == null) ? new Coin.ZERO : account.getBalance();
        return (account == null) ? new Coin(BigInteger.ZERO): account.getBalance();
    }

    @Override
    public synchronized Coin addBalance(RskAddress addr, Coin value) {
        AccountState account = getAccountStateOrCreateNew(addr);

        Coin result = account.addToBalance(value);
        updateAccountState(addr, account);

        return result;
    }

    private static byte[] stripFirstByte(byte[] str) {
        return Arrays.copyOfRange(str,1,str.length);
    }

    // This method should be used only for testing. It will retrieve the
    // account keys only in testing mode.
    @Override
    public synchronized Set<RskAddress> getAccountsKeys() {
        // This method would do two different things for a secure trie
        // than for a non-secure trie.
        int keySize;
        // a Zero prefix is used, so sizes are 20+1 and 32+1
        if (trie.isSecure()) {
            keySize = 33;
        } else {
            keySize = 21;
        }

        Set<ByteArrayWrapper>  r = trie.collectKeys(keySize );
        Set<RskAddress> result = new HashSet<>();

        if (trie.isSecure()) {
            // For each key, pass it through the inverse map
            for (ByteArrayWrapper b: r) {
                RskAddress addr = GlobalKeyMap.getGlobalAddressMap().get(b);
                result.add(addr);
            }
        } else {
            for (ByteArrayWrapper b : r) {
                result.add(new RskAddress(stripFirstByte(b.getData())));
            }
        }
        return result;

    }

    @Override
    public synchronized void dumpState(Block block, long gasUsed, int txNumber, byte[] txHash) {
        // To be implemented
    }

    // To start tracking, a new repository is created, with a MutableTrieCache in the middle
    @Override
    public synchronized Repository startTracking() {
        return new MutableRepository(new MutableTrieCache(this.getMutableTrie()));
    }

    @Override
    public synchronized void flush() {
        this.trie.save();
    }

    @Override
    public synchronized void flushNoReconnect() {
        this.flush();
    }

    @Override
    public void save() {
        this.trie.save();
    }

    @Override
    public synchronized void commit() {
        this.trie.commit();
    }

    @Override
    public synchronized void rollback() {
        this.trie.rollback();
    }

    @Override
    public synchronized void syncToRoot(byte[] root) {
        this.trie = this.trie.getSnapshotTo(new Keccak256(root));
    }

    @Override
    public synchronized boolean isClosed() {
        return this.closed;
    }

    @Override
    public synchronized void close() {
        this.closed = true;
    }

    @Override
    public void reset() {
        throw new UnsupportedOperationException();
    }

    @Override
    public synchronized void updateBatch(Map<RskAddress, AccountState> stateCache) {
        logger.debug("updatingBatch: stateCache.size: {}", stateCache.size());

        for (Map.Entry<RskAddress, AccountState> entry : stateCache.entrySet()) {
            RskAddress addr = entry.getKey();
            AccountState accountState = entry.getValue();

            if (accountState.isDeleted()) {
                delete(addr);
                logger.debug("delete: [{}]", addr);
            } else {
                updateAccountState(addr, accountState);
            }
        }
        stateCache.clear();
    }

    @Override
    public void updateBatchDetails(Map<RskAddress, ContractDetails> cacheDetails) {
        // Note: ContractDetails is only compatible with DataWord sized elements in storage!
        for (Map.Entry<RskAddress, ContractDetails> entry : cacheDetails.entrySet()) {
            RskAddress addr = entry.getKey();
            ContractDetails details = entry.getValue();
            updateContractDetails(addr,details);
        }
    }

    @Override
    public synchronized byte[] getRoot() {
        if (this.trie.hasStore()) {
            this.trie.save();
        }

        byte[] rootHash = this.trie.getHash().getBytes();
        logger.trace("getting repository root hash {}", Hex.toHexString(rootHash));
        return rootHash;
    }

    // What's the difference between startTracking() and getSnapshotTo() ?
    // getSnapshotTo() does not create a new cache layer. It just gives you
    // a view of the same Repository under another root. This means that if you
    // save data, that data will pass though ?? Yes.

    // A snapshot is a RepositoryTracker object but it's not a cache,
    // because the repository created is a MutableRepository, and
    // not a RepositoryTrack
    @Override
    public synchronized Repository getSnapshotTo(byte[] root) {
        MutableTrie atrie = this.trie.getSnapshotTo(new Keccak256(root));
        return new MutableRepository(atrie.getTrie());
    }

    @Override
    public synchronized void setSnapshotTo(byte[] root) {
        this.trie.setSnapshotTo(new Keccak256(root));
    }

    @Override
    public synchronized void updateContractDetails(RskAddress addr, final ContractDetails contractDetails){
        // Don't let a storage key live without an accountstate
        if (!isExist(addr)) {
            createAccount(addr); // if not exists
        }

        Map<DataWord, byte[]> storage = contractDetails.getStorage();
        for (Map.Entry<DataWord , byte[]> entry : storage.entrySet()) {
            addStorageBytes(addr,entry.getKey(),entry.getValue());
        }

        saveCode(addr, contractDetails.getCode());
    }

    @Override
    public synchronized void updateAccountState(RskAddress addr, final AccountState accountState) {
        byte[] accountKey = getAccountKey(addr);
        this.trie.put(accountKey, accountState.getEncoded());
        GlobalKeyMap.addAddress(accountKey,addr);
    }

    @Nonnull
    private synchronized AccountState getAccountStateOrCreateNew(RskAddress addr) {
        AccountState account = getAccountState(addr);
        return (account == null) ? createAccount(addr) : account;
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
}
