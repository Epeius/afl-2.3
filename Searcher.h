#ifndef _SEARCHER_H_
#define _SEARCHER_H_
extern "C" {
#include "types.h"
#include "config.h"
#include "debug.h"
#include "afl-searcher.h"
}

#include <stdbool.h>
#include <set>
#include <map>
#include <assert.h>
#include <cmath>
#include <random>

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

class Searcher;
// global searcher
extern "C" Searcher* AFLSearcher;

/////////////////////////////////////////////////
//            Base  Searcher                   //
/////////////////////////////////////////////////

class Searcher {
public:
    T_QE* m_queue;
    T_QE* m_queue_cur; 
public:

    Searcher(): m_queue(NULL), m_queue_cur(NULL) { }

    T_QE* getQueueCur(void) const;
    
    void setQueue(T_QE* _cur);
    void setQueueCur(T_QE* _cur);
    
    virtual ~Searcher();
    virtual T_QE* SelectNextSeed() = 0;
    virtual void onNewSeedFound(T_QE* _entry);

};

//////////////////////////////////////////////////////////////////////
// A random searcher will select randomly a seed filefrom the queue //
/////////////////////////////////////////////////////////////////////

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

///////////////////////////////////////////////////
// An ordered searcher which will try each seed  //
// file in the queue one by one.                 //
///////////////////////////////////////////////////

class OrderSearcher : public Searcher {
public:
    OrderSearcher(): Searcher() { }
    ~OrderSearcher() {}

    T_QE* SelectNextSeed() {
        m_queue_cur = m_queue_cur->next;
        return m_queue_cur;
    }

};

//////////////////////////////////////////////////////////////////////
// A CS searcher is a LOCAL optimization. The core insight is that: //
// select the most different seed with current seed based on cosine //
// similarity.                                                      //
//////////////////////////////////////////////////////////////////////

class CSSearcher : public Searcher {
protected:
    std::map<T_QE*, T_DP> m_entry_power;

    virtual u32 getSimilarityDegree(T_QE* Qa, T_QE* Qb);
public:
    CSSearcher(): Searcher() { }
    ~CSSearcher() {}

    virtual T_QE* SelectNextSeed();

    void onNewSeedFound(T_QE* _entry);
   
};

//////////////////////////////////////////////////////////////////////
// A EU searcher is a LOCAL optimization. The core insight is that: //
// select the most different seed with current seed based on eucli- //
// dienne distance similarity                                       //
//////////////////////////////////////////////////////////////////////

class EUSearcher : public CSSearcher {
public:
    EUSearcher(): CSSearcher() { }
    ~EUSearcher() {}

public:
    u32 getSimilarityDegree(T_QE* Qa, T_QE* Qb);
};


class JISearcher : public CSSearcher {
public:
    JISearcher() : CSSearcher() { }
    ~JISearcher() {}

public:
    u32 getSimilarityDegree(T_QE* Qa, T_QE* Qb);
};

#endif /* _SEARCHER_H_ */
