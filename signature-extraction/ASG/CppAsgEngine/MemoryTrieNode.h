#ifndef MEMORY_TRIE_NODE_HH
#define MEMORY_TRIE_NODE_HH
#include <iostream>
#include <boost/log/trivial.hpp>
#include "AbstractTrieNode.h"
#include "AbstractTrieNodeFactory.h"
#include "TrieNodeData.h"

template<class CTYPE,class PTYPE,unsigned int a_size> class MemoryTrieNode :
public AbstractTrieNode
{
public:
  MemoryTrieNode(AbstractTrieNodeFactory &atnf);
  MemoryTrieNode(boost::shared_ptr<TrieNodeUnion<CTYPE,PTYPE,a_size> > node,
                 AbstractTrieNodeFactory &atnf);
  virtual ~MemoryTrieNode()
  {}
  virtual void print(int indent);
  /**
   * Get accessor for leaf flag (is this node a leaf?).
   * @return True if this is a leaf, false if not.
   */
  virtual bool getLeafFlag() const
  {
    return m_node->trie_node_data.m_leaf_flag;
  }
  /**
   * Set accessor for leaf flag.
   * @param flag True if this node is now a leaf, false if not.
   */
  virtual void setLeafFlag(bool leaf_flag)
  {
    m_node->trie_node_data.m_dirty = true;
    m_node->trie_node_data.m_leaf_flag = leaf_flag;
  }
  /**
   * Get accessor for end string flag which indicates that the character
   * associated with this node is the end of a string.
   * @return True if this node is the end of a string, false if not.
   */
  virtual bool getEndStringFlag() const
  {
    return m_node->trie_node_data.m_end_string;
  }
  /**
   * Set accessor for end string flag.
   * @param flag True if this node will be the end of a string, false if not.
   */
  virtual void setEndStringFlag(bool end_string_flag)
  {
    m_node->trie_node_data.m_dirty = true;
    m_node->trie_node_data.m_end_string = end_string_flag;
  }
  /**
   * Get accessor for cleanup flag that indicates that this node needs to be
   * deleted.
   * @return True if this node needs to be deleted, false otherwise.
   */
  virtual bool getCleanupFlag() const
  {
    return m_node->trie_node_data.m_cleanup;
  }
  /**
   * Set accessor for cleanup flag that marks node for erasure.
   * @param cleanup_flag If this is true, node will be marked for eventual
   *    erasure.
   */
  virtual void setCleanupFlag(bool cleanup_flag)
  {
    m_node->trie_node_data.m_dirty = true;
    m_node->trie_node_data.m_cleanup = cleanup_flag;
  }
  /**
   * Get accessor for number of children of this node.
   * @return Number of children of this node.
   */
  virtual uint16_t getNumChildren() const
  {
    return m_node->trie_node_data.m_num_children;
  }
  /**
   * Set accessor for number of children of this node.
   * @param num_children Number of children to set.
   */
  virtual void setNumChildren(uint16_t num_children)
  {
    m_node->trie_node_data.m_dirty = true;
    m_node->trie_node_data.m_num_children = num_children;
  }
  /**
   * Get accessor to retrieve the pointer index for the node corresponding
   * to a particular character.
   * @param c Character to look up.
   * @param err_flag Reference parameter to indicate error.
   * @return Pointer index corresponding to input flag.
   */
  virtual uint64_t getChildIndex(unsigned int c,bool &err_flag) const
  {
    if(static_cast<unsigned int>(c) > static_cast<unsigned int>(a_size))
      {
        err_flag = true;
        BOOST_LOG_TRIVIAL(error)
          << "In getChildIndex, wanted char: " << c << std::endl;
        return 0;
      }

    PTYPE pointer_index = m_node->
      trie_node_data.m_tn_index[static_cast<unsigned char>(c)];

    err_flag = false;

    return pointer_index;
  }
  /**
   * Set accessor to set the pointer index for the node corresponding
   * to a particular character.
   * @param c Character to insert.
   * @param next_index Index of node that corresponds to c character.
   * @return True if successful, false if not.
   */
  virtual bool setChildIndex(unsigned int c,uint64_t next_index)
  {
    if(static_cast<unsigned int>(c) > static_cast<unsigned int>(a_size))
      {
        BOOST_LOG_TRIVIAL(error)
          << "index out of range: " << c << std::endl;
        return false;
      }
    m_node->trie_node_data.m_dirty = true;
    m_node->trie_node_data.m_tn_index[static_cast<unsigned int>(c)] =
      static_cast<PTYPE>(next_index);
    return true;
  }
  /**
   * Get accessor to retrieve the character that pointed to this node
   * from its parent.
   * @return This node's character.
   */
  virtual unsigned int getMyChar() const
  {
    return m_node->trie_node_data.m_my_c;
  }
  /**
   * Set accessor to set the character that pointed to this node
   * from its parent.
   * @param c Character to set.
   */
  virtual void setMyChar(unsigned int c)
  {
    m_node->trie_node_data.m_dirty = true;
    m_node->trie_node_data.m_my_c = static_cast<CTYPE>(c);
  }
  /**
   * Retrieve size of alphabet which is also the number of elements in the
   * array of references to the next nodes.
   * @return Number of characters in the alphabet.
   */
  virtual unsigned int getAlphabetSize() const
  {
    return a_size;
  }

private:
  boost::shared_ptr<TrieNodeUnion<CTYPE,PTYPE,a_size> > m_node;
};

template<class CTYPE,class PTYPE,unsigned int a_size>
MemoryTrieNode<CTYPE,PTYPE,a_size>::
MemoryTrieNode(AbstractTrieNodeFactory &atnf) :
  AbstractTrieNode(atnf)
{}

template<class CTYPE,class PTYPE,unsigned int a_size>
MemoryTrieNode<CTYPE,PTYPE,a_size>::MemoryTrieNode
(boost::shared_ptr<TrieNodeUnion<CTYPE,PTYPE,a_size> > node,
 AbstractTrieNodeFactory &atnf) : AbstractTrieNode(atnf),m_node(node)
{}

template<class CTYPE,class PTYPE,unsigned int a_size>
void MemoryTrieNode<CTYPE,PTYPE,a_size>::print
(int indent)
{
  std::string is(indent,'\t');
  std::cout << is << "Leaf: " <<
    ((m_node->trie_node_data.m_leaf_flag)?"T":"F") << std::endl;
  std::cout << is << "End String: "  <<
    ((m_node->trie_node_data.m_end_string)?"T":"F") <<
    std::endl;
  std::cout << is << "Cleanup Flag: "  <<
    ((m_node->trie_node_data.m_cleanup)?"T":"F") <<
    std::endl;
  std::cout << is << "Char val: 0x" << std::hex
            << (unsigned int)(m_node->trie_node_data.m_my_c)
            << std::dec << std::endl;
  std::cout << is << "Num children: " <<
    int(m_node->trie_node_data.m_num_children) <<
    std::endl;
  unsigned int child_num = 0;
  for(unsigned int i=0;i<a_size;i++)
    {
      PTYPE child_index = m_node->trie_node_data.m_tn_index[i];
      if(child_index != 0)
        {
          std::cout << is << "Child #" << child_num << std::endl;
          boost::shared_ptr<AbstractTrieNode> child_node =
            m_atnf.retrieveNode(child_index);
          child_node->print(indent+1);
          child_num++;
        }
    }
}

#endif
