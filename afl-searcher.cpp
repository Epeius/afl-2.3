#include <stdlib.h>

#include "Searcher.h"

Searcher* AFLSearcher = NULL;

/*
 * This file is the interface that connect the AFL and its searcher.
 * Any invoke to the searcher should go through this file.
 */

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
        case EUSEARCH: {
            AFLSearcher = new EUSearcher();
            break;     
        }
        case JISEARCH: {
            AFLSearcher = new JISearcher();
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

void on_new_cycle()
{
    if (!AFLSearcher)
        return;

    AFLSearcher->onNewCycle();
}

void extra_fini(T_QE* entry) 
{
    T_QE* _qe = entry;
    while (_qe) {
        delete _qe->distances;
        _qe = _qe->next;
    }
}


