// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2018 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BLOCKDB_SEQUENTIAL_H
#define BLOCKDB_SEQUENTIAL_H

#include "txdb.h"
#include "validationinterface.h"

enum FlushStateMode
{
    FLUSH_STATE_NONE,
    FLUSH_STATE_IF_NEEDED,
    FLUSH_STATE_PERIODIC,
    FLUSH_STATE_ALWAYS
};

/** Open a block file (blk?????.dat) */
FILE *OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly = false);
/** Open an undo file (rev?????.dat) */
FILE *OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly = false);
/** Translation to a filesystem path */
fs::path GetBlockPosFilename(const CDiskBlockPos &pos, const char *prefix);

void FlushBlockFile(bool fFinalize = false);

/** Flush all state, indexes and buffers to disk. */
bool FlushStateToDisk(CValidationState &state, FlushStateMode mode);
void FlushStateToDisk();
/** Prune block files and flush state to disk. */
void PruneAndFlush();


#endif // BLOCKDB_SEQUENTIAL_H
