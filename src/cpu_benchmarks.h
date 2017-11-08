#ifndef CPU_BENCHMARKS_H
#define CPU_BENCHMARKS_H

#include <stdint.h>
#include "sync.h"

extern CCriticalSection cs_block_benchmarks;

// additional info about all timers in cpu_benchmarks.cpp

/** XTHIN INFO */
extern int64_t cpu_xthin_block_time;
extern int64_t cpu_xthin_block_deserialize;
extern int64_t cpu_xthin_block_isValid_check;
extern int64_t cpu_xthin_block_header_checks;
extern int64_t cpu_xthin_availability_work_expedited;
extern int64_t cpu_xthin_store_send;
extern int64_t cpu_xthin_process;
extern int64_t cpu_xthin_process_start;
extern int64_t cpu_xthin_process_orphans;
extern int64_t cpu_xthin_process_mempool;
extern int64_t cpu_xthin_process_reconstruct;
extern int64_t cpu_xthin_process_finish;

extern int64_t cpu_end_block_process_init;
extern int64_t cpu_end_block_process_function_time;
extern int64_t cpu_end_block_process_invalid_state_time;
extern int64_t cpu_end_block_process_flightcleanup_time;
extern int64_t cpu_end_block_process_final_time;

/** XTHIN TX INFO */
extern int64_t cpu_xthin_tx_time;



/** MEMPOOL INFO */
extern int64_t cpu_mempool_time;


#endif // CPU_BENCHMARKS_H
