// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2018 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PRUNING_H
#define PRUNING_H

#include <set>
#include <stdint.h>

/**
 * Prune block and undo files (blk???.dat and undo???.dat) so that the disk space used is less than a user-defined
 * target.
 * The user sets the target (in MB) on the command line or in config file.  This will be run on startup and whenever new
 * space is allocated in a block or undo file, staying below the target. Changing back to unpruned requires a reindex
 * (which in this case means the blockchain must be re-downloaded.)
 *
 * Pruning functions are called from FlushStateToDisk when the global fCheckForPruning flag has been set.
 * Block and undo files are deleted in lock-step (when blk00003.dat is deleted, so is rev00003.dat.)
 * Pruning cannot take place until the longest chain is at least a certain length (100000 on mainnet, 1000 on testnet,
 * 1000 on regtest).
 * Pruning will never delete a block within a defined distance (currently 288) from the active chain's tip.
 * The block index is updated by unsetting HAVE_DATA and HAVE_UNDO for any blocks that were stored in the deleted files.
 * A db flag records the fact that at least some block files have been pruned.
 *
 * @param[out]   setFilesToPrune   The set of file indices that can be unlinked will be returned
 */
void FindFilesToPrune(std::set<int> &setFilesToPrune, uint64_t nPruneAfterHeight);

/**
 *  Actually unlink the specified files
 */
void UnlinkPrunedFiles(std::set<int> &setFilesToPrune);


#endif // PRUNING_H
