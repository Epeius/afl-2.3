#ifndef _AFL_SEARCHER_H
#define _AFL_SEARCHER_H
#include <stdbool.h>
#include "types.h"
#include <stdio.h>


struct queue_entry {

  u8* fname;                          /* File name for the test case      */
  u32 len;                            /* Input length                     */

  u8  cal_failed,                     /* Calibration failed?              */
      trim_done,                      /* Trimmed?                         */
      was_fuzzed,                     /* Had any fuzzing done yet?        */
      passed_det,                     /* Deterministic stages passed?     */
      has_new_cov,                    /* Triggers new coverage?           */
      var_behavior,                   /* Variable behavior?               */
      favored,                        /* Currently favored?               */
      fs_redundant;                   /* Marked as redundant in the fs?   */

  u32 bitmap_size,                    /* Number of bits set in bitmap     */
      exec_cksum;                     /* Checksum of the execution trace  */

  u64 exec_us,                        /* Execution time (us)              */
      handicap,                       /* Number of queue cycles behind    */
      depth;                          /* Path depth                       */

  u8* trace_mini;                     /* Trace bytes, if kept             */
  u8* trace_mini_persist;             /* Trace bytes, if kept             */
  u32 tc_ref;                         /* Trace bytes ref count            */

  u32* distances;                     /* Distances to each file in the queue */
  u8   was_fuzzed_by_distance;        /* whether this has been fuzzed        */
  u8   hotbytes_done;                 /* whether the hot bytes is ready      */

  struct queue_entry *next,           /* Next element, if any             */
                     *next_100;       /* 100 elements ahead               */

};

extern FILE* afl_log_file;
typedef struct queue_entry T_QE;

typedef struct distance_entry {
    u32 distance;
    T_QE* entry;
}T_DE;

enum {
    /* 00 */ RANDOMSEARCH,
    /* 01 */ CSSEARCH,
    /* 02 */ EDSEARCH,
    /* 03 */ ORDERSEARCH,
};

#ifdef _cplusplus
extern "C" {
#endif

// Initialize the searcher.
// Arg1: search_strategy: specify which searcher will use
// Arg2: the inputs_number when initializing the searcher
// Return: 1 if intilized successfully, otherwise 0.
u8 initSearcher(u8 search_strategy, u32 inputs_number);

// Main interface of searcher which is used to select next entry/seed.
// Arg: None
// Return: return next select entry/seed.
T_QE* select_next_entry();

// Initialize the searcher's queue list.
// Arg: _cur: pointer to the queue
// Return: None
void set_searcher_queue(T_QE* _cur);

// Set current entry of the searcher, this is because AFL will modify our searcher's 
// result according to its own score strategy. Should be FIXME-ed.
// Arg: _cur: pointer to current queue entry
// Return: None
void set_cur_entry(T_QE* _cur);

// Event triggered when AFL finds new path, this event enables the searcher to update its
// internal information.
// Arg: _entry: the new seed file found
// Return: None
void on_new_seed_found(T_QE* _entry);

// Free all the memory after entry node.
// Arg: entry: then entry point, should be queue's head.
void extra_fini(T_QE* entry);

#ifdef _cplusplus
}
#endif

#endif /* _AFL_SEARCHER_H */
