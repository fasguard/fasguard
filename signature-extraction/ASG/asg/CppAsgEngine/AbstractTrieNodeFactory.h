#ifndef ABSTRACT_TRIE_NODE_FACTORY_HH
#define ABSTRACT_TRIE_NODE_FACTORY_HH
#include "TrieError.h"
#include "AbstractTrieNode.h"

/**
 * This abstract class allows referencing a TrieNodeFactory without
 * specifying explicit class and type parameters.
 */
class AbstractTrieNodeFactory
{
public:
  /**
   * Constructor.  Builds map for retrieving nodes and queue for implementing
   * second-chance LRU algorithm.
   */
  AbstractTrieNodeFactory(unsigned int max_num_nodes)
    throw(DiskTrieError) :
    m_max_num_nodes(max_num_nodes)
  {}
  /**
   * Destructor.
   */
  virtual ~AbstractTrieNodeFactory()
  {}

  /**
   * Allocator.  Allocates a node on either disk or in memory and returns its
   * index.
   * @param index Sets index to the index of the new node.
   * @return boost::shared_ptr to the new node, or a null boost::shared_ptr if none can
   *    be allocated.
   */
  virtual boost::shared_ptr<AbstractTrieNode> newNode(uint64_t &index) = 0;
  /**
   * Node retrieval using index.
   * @param index Index of node to retrieve.
   * @retrun boost::shared_ptr to the retrieved node.
   */
  virtual boost::shared_ptr<AbstractTrieNode> retrieveNode(uint64_t index) = 0;
  /**
   * Delete a node by index.  This removes it from the cache and puts it on
   * the disk free list.  We also must delete all descendants.
   * @param index Index of node to delete.
   * @return True if successful, false if error.
   */
  virtual bool deleteNode(uint64_t index) = 0;
  /**
   * Flushes all nodes in cache to disk.  Typically, an expensive operation.
   * @return True if successful, false if not.
   */
  virtual bool flush2Disk() = 0;
  /**
   * Consistency check to make sure disk version is consistent and all nodes
   * both in trie and free list are accounted for and making sure memory cache
   * and disk are consistent.
   * @return True if consistent, false otherwise.
   */
  virtual bool consistencyCheck() = 0;
  /**
   * This method extends the free list in the disk trie by a desired amount.
   * @param extend_amount Number of TrieNodeData elements to add to the free
   *    list.
   * @return True if successful, false otherwise.
   */

  /**
   * This method returns the number of nodes in the trie.
   * @return Number of nodes in the Trie.
   */
  virtual unsigned int getNumNodes() const = 0;
  /**
   * This method returns the registered number of max nodes.
   * @return Maximum number of nodes desired in Trie.
   */
  unsigned int maxNumNodes() const
  {
    return m_max_num_nodes;
  }
private:
  unsigned int m_max_num_nodes;
};

#endif
