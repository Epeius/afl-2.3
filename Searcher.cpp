#include <stdio.h>
#include <assert.h>
#include <sstream>
#include <libgen.h>
#include <iostream>
#include <fstream>        

#include "Searcher.h"

using namespace std;


u8 parseLivenessFile(T_QE* entry);

/////////////////////////////////////////////////
//           Searchers                         //
/////////////////////////////////////////////////

Searcher::~Searcher()
{

}

T_QE* Searcher::getQueueCur() const
{
    return m_queue_cur;
}

void Searcher::setQueue(T_QE* _cur) 
{
    m_queue = _cur;
}

void Searcher::setQueueCur(T_QE* _cur)
{
    m_queue_cur = _cur;
}

void Searcher::markAsFuzzed(T_QE* _cur)
{
    m_unFuzzedinCycle.erase(_cur->id);
}

void Searcher::onNewCycle()
{
    m_unFuzzedinCycle = m_queuedIDs;
}

void Searcher::onNewSeedFound(T_QE* _entry) 
{
    m_unFuzzedinCycle.insert(_entry->id);
    m_queuedIDs.insert(_entry->id);
}

u32 Searcher::getFuzzedNumber()
{
    return m_queuedIDs.size() - m_unFuzzedinCycle.size();
}

u32 CSSearcher::getSimilarityDegree(T_QE* Qa, T_QE* Qb) 
{
    if (!Qa->trace_mini_persist) {
        char msg [512];
        sprintf(msg, "Cannot find mini trace for %s\n", Qa->fname);
        fputs(msg, afl_log_file);
        return 0;
    }

    if (!Qb->trace_mini_persist) {
        char msg [512];
        sprintf(msg, "Cannot find mini trace for %s\n", Qb->fname);
        fputs(msg, afl_log_file);
        return 0;
    }

    double dot = 0.0, denom_a = 0.0, denom_b = 0.0 ;
    for(unsigned int i = 0u; i < (MAP_SIZE >> 3); i++) {
        dot += Qa->trace_mini_persist[i] * Qb->trace_mini_persist[i];
        denom_a += Qa->trace_mini_persist[i] * Qa->trace_mini_persist[i];
        denom_b += Qb->trace_mini_persist[i] * Qb->trace_mini_persist[i];
    }
    double cs_normarized = dot / (sqrt(denom_a) * sqrt(denom_b));

    // integer-ize to 0 ~ 10000
    u32 cs = 10000 - (u32)(cs_normarized * 10000);
    return cs;
}

// When new seed is found, calculate the CS to each seed already in the queue.
void CSSearcher::onNewSeedFound(T_QE* _entry)
{
    Searcher::onNewSeedFound(_entry);
    // first time
    if (m_queue == _entry) {
        T_DP _new_dp;
        m_entry_power.insert(std::make_pair(_entry, _new_dp));
        return;
    }
    T_QE* _tmp = m_queue;
    while (_tmp) {
        if (_tmp == _entry) {
            _tmp = _tmp->next;
            continue;
        }
        
        u32 csd = getSimilarityDegree(_tmp, _entry);
        
        if (m_entry_power.find(_tmp) == m_entry_power.end()) {
            char msg[512];
            sprintf(msg, "Cannot find entry_power for %s\n", _tmp->fname);
            fputs(msg, afl_log_file);
            exit(-1);
        }

        T_DE de;
        de.distance = csd;
        de.entry    = _entry;

        m_entry_power[_tmp].distance.insert(de);
        m_entry_power[_tmp].calculated_entry.insert(_entry);

        if (m_entry_power.find(_entry) == m_entry_power.end()) {
            T_DP _new_dp;
            m_entry_power.insert(std::make_pair(_entry, _new_dp));
        }

        T_DE new_de;
        new_de.distance = csd;
        new_de.entry    = _tmp;

        m_entry_power[_entry].distance.insert(new_de);
        m_entry_power[_entry].calculated_entry.insert(_tmp);

        _tmp = _tmp->next;
    }
}

T_QE* CSSearcher::SelectNextSeed() 
{
    std::set<T_DE, comp> distance = m_entry_power[m_queue_cur].distance;
    for (auto it = distance.begin(), end = distance.end(); it != end; it++) {
        T_DE _t_dis_entry = *it;
        if (!_t_dis_entry.entry->was_fuzzed_by_distance) {
            _t_dis_entry.entry->was_fuzzed_by_distance = 1;
            char msg[512];
            sprintf(msg, "selected %s, distance is %d\n", _t_dis_entry.entry->fname, _t_dis_entry.distance);
            fputs(msg, afl_log_file);
            Searcher::markAsFuzzed(_t_dis_entry.entry);
            return _t_dis_entry.entry;
        }
    }

    // Reaching here means all the entries have been fuzzed already, 
    // then return NULL to force enter a new cycle.
    T_QE* _tmp_entry = m_queue;
    while (_tmp_entry) {
        _tmp_entry->was_fuzzed_by_distance = 0;
        _tmp_entry = _tmp_entry->next;
    }
    char msg[256];
    sprintf(msg, "all fuzzed, go to next cycle\n");
    fputs(msg, afl_log_file);

    return NULL;

}

u32 EUSearcher::getSimilarityDegree(T_QE* Qa, T_QE* Qb)
{
    if (!Qa->trace_mini_persist) {
        char msg [512];
        sprintf(msg, "Cannot find mini trace for %s\n", Qa->fname);
        fputs(msg, afl_log_file);
        return 0;
    }

    if (!Qb->trace_mini_persist) {
        char msg [512];
        sprintf(msg, "Cannot find mini trace for %s\n", Qb->fname);
        fputs(msg, afl_log_file);
        return 0;
    }

    double dot = 0.0;
    for(unsigned int i = 0u; i < (MAP_SIZE >> 3); i++) {
        u32 sd = abs((u8)(Qa->trace_mini_persist[i]) - (u8)(Qb->trace_mini_persist[i]));
        dot += (sd * sd); // not overflow here (SAFE)
    }
    double eu = sqrt(dot);

    return (u32)eu;
}

u32 JISearcher::getSimilarityDegree(T_QE* Qa, T_QE* Qb)
{
    if (!Qa->trace_mini_persist) {
        char msg [512];
        sprintf(msg, "Cannot find mini trace for %s\n", Qa->fname);
        fputs(msg, afl_log_file);
        return 0;
    }

    if (!Qb->trace_mini_persist) {
        char msg [512];
        sprintf(msg, "Cannot find mini trace for %s\n", Qb->fname);
        fputs(msg, afl_log_file);
        return 0;
    }

    double JIV = 0.0, denom_a = 0.0, denom_b = 0.0;
    for(unsigned int i = 0u; i < (MAP_SIZE >> 3); i++) {
        JIV += Qa->trace_mini_persist[i] * Qb->trace_mini_persist[i];
        denom_a += Qa->trace_mini_persist[i] * Qa->trace_mini_persist[i];
        denom_b += Qb->trace_mini_persist[i] * Qb->trace_mini_persist[i];
    }

    JIV = JIV / (denom_a + denom_b - JIV);
    
    u32 dis = 1000 - (u32)(JIV * 1000);
    return (u32)dis;
}

//////////////////////////////////////////////////////
/////////////////////////////////////////////////////

// TODO: Distance searcher
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
    //initEntry(entry);

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