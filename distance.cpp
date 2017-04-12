#include <stdio.h>
#include <set>
#include <map>
#include <assert.h>
#include <sstream>
#include <libgen.h>
#include <iostream>
#include <fstream>        
#include <cmath>

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
    // bytes that affect the path constraints  <offset, value>
    std::map<u32, u8> hot_bytes;
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

    /*
     * The distance is quite simple now, accumulate the difference for 
     * each hot byte.
     */
    ifstream Qb_file((const char*)Qb->fname, ifstream::binary);
    if (!Qb_file)
        exit(-1);

    Qb_file.seekg (0, Qb_file.end);
    u32 Qb_len = Qb_file.tellg();
    Qb_file.seekg (0, Qb_file.beg);


    u32 distance_value = 0;

    std::map<u32, u8> hot_bytes = ((T_DP*)Qa->distances)->hot_bytes;
    
    for (auto it = hot_bytes.begin(), end = hot_bytes.end(); it != end; it++) {
        u32  offset = it->first;
        u8   Qa_value = (u8)it->second;
        char Qb_value;
        
        if (offset >= Qb_len)
            continue;
        
        Qb_file.seekg(offset, Qb_file.beg);
        Qb_file.read(&Qb_value, 1);

        distance_value  += abs(Qa_value - (u8)Qb_value);
    }

    Qb_file.close();

    return distance_value;
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
            if (!parseLivenessFile(_t_dis_entry.entry)) {
                continue;
            }
            _t_dis_entry.entry->was_fuzzed_by_distance = 1;
            char msg[512];
            sprintf(msg, "selected %s, distance is %d\n", _t_dis_entry.entry->fname, _t_dis_entry.distance);
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
    if (entry->hotbytes_done)
        return 1;
    std::stringstream liveness_file;
    std::string curName(basename((char*)entry->fname));
    liveness_file << "livenesses/" << curName << ".liveness";

    FILE* liveness_fp = fopen(liveness_file.str().c_str(), "r");
    if (liveness_fp <= 0) {
        //PFATAL("Cannot open liveness file.");
        return 0;
    }

    // collecting hot bytes
    initEntry(entry);

    T_DP* entry_dp = (T_DP*)(entry->distances);
    assert(entry_dp);

    ifstream seed_file((const char*)entry->fname, ifstream::binary);
    if (!seed_file)
        exit(-1);

    char value;
    u32 offset, liveness;
    while (EOF != fscanf(liveness_fp, "%d-%d\n", &offset, &liveness)) {
        seed_file.seekg(offset, seed_file.beg);
        seed_file.read(&value, 1);
        entry_dp->hot_bytes.insert(std::make_pair(offset, (u8)value));
    }

    fclose(liveness_fp);
    seed_file.close();
    entry->hotbytes_done = 1;
    return 1;
}
