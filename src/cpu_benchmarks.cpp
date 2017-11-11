#if defined(ENABLE_CPUBENCHMARK)
#include "cpu_benchmarks.h"
#endif

/** XTHIN INFO */
CCriticalSection cs_block_benchmarks;

/** This first set is for the handle message call */
//CXThinBlock::HandleMessage()
int64_t cpu_xthin_block_time = 0;

//vRecv >> thinBlock;
int64_t cpu_xthin_block_deserialize = 0;

//IsThinBlockValid()
int64_t cpu_xthin_block_isValid_check = 0;

//mapBlockIndex.find(prevHash) + AcceptBlockHeader + !pindex
int64_t cpu_xthin_block_header_checks = 0;

//UpdateBlockAvailability + ClearThinBlockData + IsExpeditedUpstream + AddThinBlockInFlight + mapThinBlocksInFlight.count ||| AT MOST
int64_t cpu_xthin_availability_work_expedited = 0;

//IsRecentlyExpeditedAndStore + SendExpeditedBlock
int64_t cpu_xthin_store_send = 0;

//thinBlock.process
int64_t cpu_xthin_process = 0;

// bunch of misc constructors and setters and stuff
int64_t cpu_xthin_process_start = 0;

//mapOrphanTransactions iterate through + set collision
int64_t cpu_xthin_process_orphans = 0;

//mempool.queryHashes + iterate through all hashes + pfrom->mapMissingTx iteration + foreach on vTxHashes + ComputeMerkleRoot + ReconstructBlock ||| AT MOST
int64_t cpu_xthin_process_mempool = 0;

//ReconstructBlock
int64_t cpu_xthin_process_reconstruct = 0;

//finish up function, lauch process block thread and do remaining collision checks
int64_t cpu_xthin_process_finish = 0;

/** these are for processing the block itself */
//pthread init + ChainParams()
int64_t cpu_end_block_process_init = 0;

//ProcessNewBlock()
int64_t cpu_end_block_process_function_time = 0;

//state.Valid + findMostWorkChain() + LargestBlockSeen
int64_t cpu_end_block_process_invalid_state_time = 0;

//ClearThinBlockData + thinblock cleanup functions
int64_t cpu_end_block_process_flightcleanup_time = 0;

//PV cleanup functions
int64_t cpu_end_block_process_final_time = 0;


/** XTHIN TX INFO */
int64_t cpu_xthin_tx_time = 0;






/** MEMPOOL INFO */
int64_t cpu_mempool_time = 0;

