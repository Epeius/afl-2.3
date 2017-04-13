#include <stdio.h>
#include <set>
#include <map>
#include <assert.h>
#include <sstream>
#include <libgen.h>
#include <iostream>
#include <fstream>        
#include <cmath>
#include <random>

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

class Searcher;

// global searcher
Searcher* AFLSearcher = NULL;

/////////////////////////////////////////////////
//           Searchers                         //
/////////////////////////////////////////////////

class Searcher {
public:
    T_QE* m_queue;
    T_QE* m_queue_cur; 
public:

    Searcher(): m_queue(NULL), m_queue_cur(NULL) { }

    T_QE* getQueueCur(void) const { return m_queue_cur; }
    
    void setQueue(T_QE* _cur) { m_queue = _cur; }
    void setQueueCur(T_QE* _cur) { m_queue_cur = _cur; }
    
    virtual ~Searcher() { }
    virtual T_QE* SelectNextSeed() = 0;
    virtual void onNewSeedFound(T_QE* _entry) { }

};

/*
 * A CS searcher is a LOCAL optimization. The core insight is that:
 * select the most different seed with current seed based on cosine 
 * similarity.
 */
class CSSearcher : public Searcher {
private:
    std::map<T_QE*, T_DP> m_entry_power;

    u32 getCSdegree(T_QE* Qa, T_QE* Qb);
public:
    CSSearcher(): Searcher() { }
    ~CSSearcher() {}

    T_QE* SelectNextSeed();

    void onNewSeedFound(T_QE* _entry);
   
};

u32 CSSearcher::getCSdegree(T_QE* Qa, T_QE* Qb) 
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
        
        u32 csd = getCSdegree(_tmp, _entry);
        
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
            return _t_dis_entry.entry;
        }
    }

    // Reaching here means all the entries have been fuzzed already, then use the 
    // logic of AFL itself to select.
    T_QE* _tmp_entry = m_queue;
    while (_tmp_entry) {
        _tmp_entry->was_fuzzed_by_distance = 0;
        _tmp_entry = _tmp_entry->next;
    }
    char msg[256];
    sprintf(msg, "all fuzzed, go to next cycle\n");
    fputs(msg, afl_log_file);

    return m_queue_cur->next;

}

/*
 * A random searcher will select randomly a seed filefrom the queue.
 */
class RandomSearcher : public Searcher {
private:
    u32 m_total_paths;
    std::mt19937 m_rnd;
public:
     RandomSearcher(): Searcher() {
         m_total_paths = 0;
     }

    ~RandomSearcher() {}

    T_QE* SelectNextSeed() {

        assert(m_total_paths && "No seed files?");

        std::uniform_int_distribution<> dis(0, m_total_paths - 1);
        u32 off = dis(m_rnd);
        T_QE* _tmp = m_queue;
        while (off) {
            _tmp = _tmp->next;
            off--;
        }

        return _tmp;
    }

    void onNewSeedFound(T_QE* _entry) {
        m_total_paths += 1;
    }
};

/*
 * An ordered searcher which will try each seed file in the queue
 * one by one.
 */
class OrderSearcher : public Searcher {
public:
    OrderSearcher(): Searcher() { }
    ~OrderSearcher() {}

    T_QE* SelectNextSeed() {
        m_queue_cur = m_queue_cur->next;
        return m_queue_cur;
    }

};

/////////////////////////////////////////////////
//           Interfaces to fuzzer              //
/////////////////////////////////////////////////

u8 initSearcher(u8 search_strategy, u32 inputs_number)
{
    switch (search_strategy) {
        case ORDERSEARCH: {
            AFLSearcher = new OrderSearcher();
            break;     
        }
        case RANDOMSEARCH: {
            AFLSearcher = new RandomSearcher();
            break;     
        }
        case CSSEARCH: {
            AFLSearcher = new CSSearcher();
            break;     
        }

        default:
            break;
    }

    return 1;
}

T_QE* select_next_entry(void) 
{
    return AFLSearcher->SelectNextSeed();
}

void set_searcher_queue(T_QE* _cur)
{
    if (!AFLSearcher)
        return;
    
    assert(!AFLSearcher->m_queue && "Already initialized the queue?");

    AFLSearcher->m_queue = _cur;
}

void set_cur_entry(T_QE* _cur)
{
    AFLSearcher->setQueueCur(_cur);
}

void on_new_seed_found(T_QE* _entry)
{
    if (!AFLSearcher)
        return;

    AFLSearcher->onNewSeedFound(_entry);
}

u8 initEntry(T_QE* entry) 
{
    if (entry->distances == NULL) {
        T_DP* _t_dp = new T_DP();
        entry->distances = (u32*)_t_dp;
    }

    return 1;
}

/*
 * Caculate Cosine Similarity for two entries.
 */
u32 getCS(T_QE* Qa, T_QE* Qb)
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
    for(unsigned int i = 0u; i < MAP_SIZE; i++) {
        dot += Qa->trace_mini_persist[i] * Qb->trace_mini_persist[i];
        denom_a += Qa->trace_mini_persist[i] * Qa->trace_mini_persist[i];
        denom_b += Qb->trace_mini_persist[i] * Qb->trace_mini_persist[i];
    }
    double cs_normarized = dot / (sqrt(denom_a) * sqrt(denom_b));

    // integer-ize to 0 ~ 10000
    u32 cs = 10000 - (u32)(cs_normarized * 10000);
    return cs;
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
            //u32 dis_value = getDistance(entry, _tmp_entry);
            u32 dis_value = getCS(entry, _tmp_entry);
            
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
            //if (!parseLivenessFile(_t_dis_entry.entry)) {
            //    continue;
            //}
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
