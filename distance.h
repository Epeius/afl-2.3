#ifndef _DISTANCE_H_
#define _DISTANCE_H_
#include <stdbool.h>
#include "types.h"


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
  u32 tc_ref;                         /* Trace bytes ref count            */

  u32* distances;                     /* Distances to each file in the queue */
  u8   was_fuzzed_by_distance;        /* whether this has been fuzzed        */
  u8   hotbytes_done;                 /* whether the hot bytes is ready      */

  struct queue_entry *next,           /* Next element, if any             */
                     *next_100;       /* 100 elements ahead               */

};

extern FILE* afl_log_file;
#ifdef _cplusplus
extern "C" struct queue_entry;
#endif
#ifdef _cplusplus
extern "C" {
#endif
    struct queue_entry *queue,     /* Fuzzing queue (linked list)      */
                   *queue_cur, /* Current offset within the queue  */
                   *queue_top, /* Top of the list                  */
                   *q_prev100; /* Previous 100 marker              */
#ifdef _cplusplus
}
#endif

#ifdef _cplusplus
extern "C" {
#endif

typedef struct queue_entry T_QE;

typedef struct distance_entry {
    u32 distance;
    T_QE* entry;
}T_DE;

#ifdef _cplusplus
}
#endif

/* Function Defines */
#ifdef _cplusplus
extern "C" {
#endif
// Initialize the distance power instruction
// Arg: entry: the current queue entry
// Return: 1 if intilized successfully, otherwise 0.
u8 initEntry(T_QE* entry);

// Calculate the distance between different files.
// Arg1: Qa: template file
// Arg2: Qb: the other file
// Return: The distance which is an u32 integer.
u32 getDistance(T_QE* Qa, T_QE* Qb);

// Get the seed that has longgest distance to current queue entry.
// Arg1: entry: current queue entry
// Arg2: queue: the queue instance
// Return: The queue entry.
T_QE* getFurthestEntry(T_QE* entry, T_QE* queue);

// Free all the memory after entry node.
// Arg: entry: then entry point, should be queue's head.
void distance_fini(T_QE* entry);

#ifdef _cplusplus
}
#endif 

#endif /* _DISTANCE_H_ */
