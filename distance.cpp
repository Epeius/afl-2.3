#include <stdio.h>
#include <map>
#include <set>
#include <assert.h>
#include <sstream>
#include <libgen.h>
#include <new> 

extern "C" {
#include "config.h"
#include "debug.h"
#include "distance.h"
}

using namespace std;

struct comp {
    bool operator ()(const T_DE& deA, const T_DE& deB) {
        return (deA.distance >= deB.distance);
    }
};

typedef struct distance_power {
    // ordered-set to store all the distances and it's queue_entry
    std::set<T_DE, comp> distance;
    // collection of all queue_entry-s that the distance have been generated
    std::set<T_QE*> calculated_entry;
    // bytes that affect the path constraints 
    std::set<u32> hot_bytes;
}T_DP;

u8 parseLivenessFile(T_QE* entry);
/////////////////////////////////////////////////
//           Interfaces to fuzzer              //
/////////////////////////////////////////////////

u8 initEntry(T_QE* entry) 
{
    if (entry->distances == NULL) {
        T_DP* _t_dp = new T_DP();
        entry->distances = (u32*)_t_dp;
    }
    
    return 1;
}

u32 getDistance(T_QE* Qa, T_QE* Qb)
{
    if (!Qa->hotbytes_done) {
        if (!parseLivenessFile(Qa))
            return 0;
        Qa->hotbytes_done = 1;

        if (((T_DP*)Qa->distances)->hot_bytes.size() == 0)
            return 0;
    }

    // TODO: calculate distance

    return 0;
}

T_QE* getFurthestEntry(T_QE* entry, T_QE* queue)
{
    // First check which queue_entry's distance has not been calculated.
    T_QE* _tmp_entry = queue;
    std::set<T_QE*> dis_entries = ((T_DP*)entry->distances)->calculated_entry;
    while (_tmp_entry) {
        if (entry == _tmp_entry) {
	       _tmp_entry = _tmp_entry->next;	
	       continue;
	}
        if (dis_entries.find(_tmp_entry) == dis_entries.end()) {
            // If not has been caculated, then caculate this and update the T_DP structure.
            u32 dis_value = getDistance(entry, _tmp_entry);
            
            T_DE de;
            de.distance = dis_value;
            de.entry    = _tmp_entry;

            ((T_DP*)entry->distances)->distance.insert(de);
            ((T_DP*)entry->distances)->calculated_entry.insert(_tmp_entry);
        }

        _tmp_entry = _tmp_entry->next;
    }

    u32 dis_entry_size = ((T_DP*)entry->distances)->distance.size();
    if (!dis_entry_size)
        return entry->next;

    std::set<T_DE, comp> distance = ((T_DP*)entry->distances)->distance;
    for (auto it = distance.begin(), end = distance.end(); it != end; it++) {
        T_DE _t_dis_entry = *it;
        if (!_t_dis_entry.entry->was_fuzzed_by_distance) {
            _t_dis_entry.entry->was_fuzzed_by_distance = 1;
	    char msg[256];
	    sprintf(msg, "selected %s\n", _t_dis_entry.entry->fname);
	    fputs(msg, afl_log_file);
            return _t_dis_entry.entry;
        }
    }

    // Reaching here means all the entries have been fuzzed already, then use the 
    // logic of AFL itself to select.
    _tmp_entry = queue;
    while (_tmp_entry) {
        _tmp_entry->was_fuzzed_by_distance = 0;
        _tmp_entry = _tmp_entry->next;
    }
    char msg[256];
    sprintf(msg, "all fuzzed, go to next cycle\n");
    fputs(msg, afl_log_file);

    return entry->next;
}

void distance_fini(T_QE* entry)
{
    T_QE* _qe = entry;
    while (_qe) {
        delete _qe->distances;
        _qe = _qe->next;
    }
}

//////////////////////////////////////////////////////
/////////////////////////////////////////////////////

u8 parseLivenessFile(T_QE* entry) 
{
    std::stringstream liveness_file;
    std::string curName(basename((char*)entry->fname));
    liveness_file << "livenesses/" << curName << ".liveness";

    FILE* liveness_fp = fopen(liveness_file.str().c_str(), "r");
    if (liveness_fp <= 0) {
        //PFATAL("Cannot open liveness file.");
        return 0;
    }

    // collecting hot bytes
    T_DP* entry_dp = (T_DP*)(entry->distances);
    assert(entry_dp);

    u32 offset, liveness;
    while (EOF != fscanf(liveness_fp, "%d-%d\n", &offset, &liveness)) {
        entry_dp->hot_bytes.insert(offset);
    }

    fclose(liveness_fp);
    return 1;
}
