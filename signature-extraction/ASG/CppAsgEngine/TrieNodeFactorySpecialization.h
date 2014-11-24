#ifndef TRIE_NODE_FACTORY_SPECIALIZATION_HH
#define TRIE_NODE_FACTORY_SPECIALIZATION_HH
#include <string>
#include "AbstractTrieNodeFactory.h"

extern
AbstractTrieNodeFactory &
TNFInstance(std::string disk_cache_filename = "DiskCache.tnf",
            unsigned int memory_cache_size = 800000,
            unsigned int disk_cache_size = 1000000,
            unsigned int disk_extend_amount = 400000);

#endif
