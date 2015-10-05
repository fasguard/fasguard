#ifndef MEMORY_TRIE_NODE_FACTORY_HH
#define MEMORY_TRIE_NODE_FACTORY_HH
#include <fstream>
#include <map>
#include <queue>
#include <utility>
#include <algorithm>
#include <sys/time.h>
#include <stdint.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <boost/shared_ptr.hpp>
#include <boost/log/trivial.hpp>

#include "AbstractTrieNode.h"
#include "AbstractTrieNodeFactory.h"
#include "TrieError.h"
#include "TrieNodeData.h"
//#include "HashMap.h"
#include "MemoryTrieNode.h"
#include "TrieNodeFactorySpecialization.h"

using namespace std;
/**
 * This templated class creates TrieNodes, either in memory or on disk
 */
template<class CTYPE,class PTYPE,unsigned int a_size>
class MemoryTrieNodeFactory : public AbstractTrieNodeFactory
{
public:
  /**
   * Constructor.  Builds hash for retrieving nodes.
   */
  MemoryTrieNodeFactory(unsigned int max_num_nodes = 5000000);
  /**
   * Destructor.
   */
  ~MemoryTrieNodeFactory()
  {
  }

  /**
   * Allocator.  Allocates a node on either disk or in memory and returns its
   * index.
   * @param index Sets index to the index of the new node.  This is a uint64
   *    to allow for longest possible index.
   * @return boost::shared_ptr to the new node, or a null boost::shared_ptr if none can
   *    be allocated.
   */
  boost::shared_ptr<AbstractTrieNode> newNode(uint64_t &index);
  /**
   * Node retrieval using index.
   * @param index Index of node to retrieve.
   * @return boost::shared_ptr to the retrieved node, null boost::shared_ptr if not found.
   */
  boost::shared_ptr<AbstractTrieNode> retrieveNode(uint64_t index);
  /**
   * Delete a node by index.  This removes it from the cache and puts it on
   * the disk free list.  All descendents are also deleted.
   * @param index Index of node to delete.
   * @return True if successful, false if error.
   */
  bool deleteNode(uint64_t index);
  /**
   * Flushes all nodes in cache to disk.  Typically, an expensive operation.
   * @return True if successful, false if not.
   */
  bool flush2Disk();
  /**
   * Consistency check to make sure disk version is consistent and all nodes
   * both in trie and free list are accounted for and making sure memory cache
   * and disk are consistent.
   * @return True if consistent, false otherwise.
   */
  bool consistencyCheck();
  /**
   * This method returns the number of nodes in the trie.
   * @return Number of nodes in the Trie.
   */
  unsigned int getNumNodes() const
  {
    return m_trie_node_hash.size();
  }
private:
  bool deleteAssistant(std::stack<PTYPE> &delete_stack);
  typedef TrieNodeUnion<CTYPE,PTYPE,a_size> TrieNodeUnionType;
  typedef boost::shared_ptr<TrieNodeUnion<CTYPE,PTYPE,a_size> > TrieNodeDataSPtr;
  std::map<PTYPE,TrieNodeDataSPtr> m_trie_node_hash;
  //std::map<PTYPE,TrieNodeDataSPtr> m_trie_node_hash;
  unsigned int m_next_node_index;
};

template<class CTYPE,class PTYPE,unsigned int a_size>
MemoryTrieNodeFactory<CTYPE,PTYPE,a_size>::MemoryTrieNodeFactory
(unsigned int max_num_nodes)  :
  AbstractTrieNodeFactory(max_num_nodes),m_next_node_index(0)
{
  // Create root node

  TrieNodeDataSPtr
    root_node(new TrieNodeUnion<CTYPE,PTYPE,a_size>);
  root_node->trie_node_data.m_leaf_flag = true;
  root_node->trie_node_data.m_end_string = false;
  root_node->trie_node_data.m_cleanup = false;
  root_node->trie_node_data.m_parent_size = 0;
  root_node->trie_node_data.m_num_children = 0;
  root_node->trie_node_data.m_num_insertions = 0;
  for(register unsigned int i=0;i<a_size;i++)
    root_node->trie_node_data.m_tn_index[i] = 0;

  m_trie_node_hash[m_next_node_index++] = root_node;
}

template<class CTYPE,class PTYPE,unsigned int a_size>
boost::shared_ptr<AbstractTrieNode>
MemoryTrieNodeFactory<CTYPE,PTYPE,a_size>::newNode(uint64_t &index)
{
  // First, get new index value

  index = m_next_node_index++;

  boost::shared_ptr<TrieNodeUnion<CTYPE,PTYPE,a_size> >
    tnd(new TrieNodeUnion<CTYPE,PTYPE,a_size>);
  boost::shared_ptr<AbstractTrieNode>
    mtn(new MemoryTrieNode<CTYPE,PTYPE,a_size>(tnd,*this));

  // Initialize new node

  tnd->trie_node_data.m_leaf_flag = true;       // New node is a leaf node
  tnd->trie_node_data.m_end_string = false;
  tnd->trie_node_data.m_cleanup = false;
  for(register unsigned int i=0;i<a_size;i++)
    tnd->trie_node_data.m_tn_index[i] = 0;
  tnd->trie_node_data.m_touched = false;

  // Put node in hash
  m_trie_node_hash[static_cast<PTYPE>(index)] = tnd;

  return mtn;
}

template<class CTYPE,class PTYPE,unsigned int a_size>
boost::shared_ptr<AbstractTrieNode>
MemoryTrieNodeFactory<CTYPE,PTYPE,a_size>::retrieveNode(uint64_t index)
{
  // First, check if in hashmap

  typename
    std::map<PTYPE,boost::shared_ptr<TrieNodeUnion<CTYPE,PTYPE,a_size> > >::
    iterator it;
    //typename map<PTYPE,SmartPtr<TrieNodeUnion<CTYPE,PTYPE,a_size> > >::iterator
    //it;

  it = m_trie_node_hash.find(static_cast<PTYPE>(index));

  if(it == m_trie_node_hash.end())
    {
      BOOST_LOG_TRIVIAL(error)
        << "Failed to retrieve: " << index
        << ", next index: " << m_next_node_index
        << endl;
      return boost::shared_ptr<AbstractTrieNode>((AbstractTrieNode *)NULL);
    }
  else
    {
      return
        boost::shared_ptr<AbstractTrieNode>(new MemoryTrieNode<CTYPE,PTYPE,
                                            a_size>
                                   ((*it).second,*this));
    }
}


template<class CTYPE,class PTYPE,unsigned int a_size>
bool MemoryTrieNodeFactory<CTYPE,PTYPE,a_size>::flush2Disk()
{
  return true;
}


template<class CTYPE,class PTYPE,unsigned int a_size>
bool
MemoryTrieNodeFactory<CTYPE,PTYPE,a_size>::consistencyCheck()
{
  return true;
}

template<class CTYPE,class PTYPE,unsigned int a_size>
bool
MemoryTrieNodeFactory<CTYPE,PTYPE,a_size>::deleteNode(uint64_t index)
{
  std::stack<PTYPE> node_stack;
  node_stack.push(index);
  if(!deleteAssistant(node_stack))
    {
      return false;
    }
  while(!node_stack.empty())
    {
      BOOST_LOG_TRIVIAL(error)
        << "Node Stack elem="
        << node_stack.top()
        << endl;
      typename std::map<PTYPE,TrieNodeDataSPtr>::iterator it =
        //typename map<PTYPE,TrieNodeDataSPtr>::iterator it =
        m_trie_node_hash.find(node_stack.top());
      m_trie_node_hash.erase(it);
      node_stack.pop();
    }
  return true;
}

template<class CTYPE,class PTYPE,unsigned int a_size>
bool
MemoryTrieNodeFactory<CTYPE,PTYPE,a_size>::deleteAssistant
(std::stack<PTYPE> &delete_stack)
{
  boost::shared_ptr<AbstractTrieNode> cur_node =
    retrieveNode(delete_stack.top());
    for(register unsigned int i=0;i<cur_node->getAlphabetSize();i++)
    {
      bool err_flag;
      uint64_t child_index = cur_node->getChildIndex(i,err_flag);
      if(err_flag)
        return false;
      if(child_index == 0)
        continue;

      delete_stack.push(child_index);
      if(deleteAssistant(delete_stack))
        return false;
    }
  return true;
}

#endif
