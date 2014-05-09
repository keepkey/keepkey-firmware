#include <unistd.h>

#include <foundation/foundation.h>

#include <storage.pb.h>

#include <wallet.h>

/**
 * posix implementation
 */
namespace cd {
    const char walletfile[] = "wallet.dat";

    void hdnode_from_storage(Storage& storage, HDNode& node)
    {
        
        hdnode_from_xprv(storage.node.depth,
                         storage.node.fingerprint,
                         storage.node.child_num,
                         storage.node.chain_code.bytes,
                         storage.node.private_key.bytes,
                         &node);
    }

    bool Wallet::load_from_file()
    {

        int fd=-1;

        /*
         * Read in the node from the wallet file.  Do some basic validation.
         * FIXME: Add a storage backend
         */
        AbortIfNot(open_file(walletfile, fd), false, "Wallet file (%s) not found.\n", walletfile);

        Storage storage;
        ssize_t sz = read(fd, &storage, sizeof(storage)); 
        close(fd);

        AbortIf(sz != sizeof(storage), false, "Invalid storage file. sz=%d\n", sz);

        AbortIf(storage.has_node == false, false, "Storage missing hdnode.\n");

        hdnode_from_storage(storage, root_node);

        return true;
    }

    bool Wallet::store()
    {
        AbortIf(is_file(walletfile), false, "Wallet file (%s) already exists.  Aborting.\n", walletfile);

        int fd=-1;
        AbortIfNot(make_log_file(fd, walletfile), false, "Failed to make wallet file.\n");


        ssize_t sz = write(fd, &root_node, sizeof(root_node));
        close(fd);

        AbortIf(sz != sizeof(root_node), false, "Failed to write wallet file.\n");

        return true;
    }
}
