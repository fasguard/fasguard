#ifndef TRIE_NODE_DATA_HH
#define TRIE_NODE_DATA_HH
#include <stdint.h>
#include <ctime>
#include <sys/time.h>

template<class CTYPE,class PTYPE,unsigned int a_size> struct TrieNodeData
{
  bool m_leaf_flag : 1;         // Is this node a leaf
  bool m_end_string : 1;        // Does this node end a string?
  bool m_cleanup : 1;           // Used in some operations to mark this
                                // node for erasure
  bool m_touched : 1;           // For caching, indicates that the node
                                // has been touched
  bool m_dirty : 1;             // Indicates that node has been modified
  CTYPE m_my_c;                 // The character used to transition to this
                                // node from the node above
  uint32_t m_parent_size;
  PTYPE m_parent_index;
  //  CTYPE m_c_array[a_size];
  uint16_t m_num_children;
  PTYPE m_tn_index[a_size];
  uint32_t m_num_insertions;
};

const static uint32_t HeaderLengthInBytes = 4096;
const static uint32_t CurTrieNodeVer = 1;
const static uint32_t ByteOrderingTest = 0x12345678;
const static uint32_t CommentLength = 512;
const static uint32_t FieldPaddingInU32 = 128;
const static uint32_t TrieMagicNumber = 0x54524945;  // TRIE

template<class PTYPE> struct TrieFileHeader
{
  uint32_t magic_number;                // Magic number to identify file type
  uint32_t byte_ordering_test;          // Pattern for detecting byte swapping
  uint32_t version;                     // Current version
  uint32_t cur_length;                  // Current number of TrieNodeData
                                        // entries
  struct timeval creation;              // Time of creation of file
  struct timeval last_close;            // Time Trie DB was last closed
  uint32_t header_checksum;             // Header checksum (including padding)
  PTYPE root_index;                     // Index of root node
  PTYPE free_list_head;                 // Index of start of free list
  PTYPE num_free;                       // Number of nodes on the free list
  PTYPE num_tree_nodes;                 // Number of nodes in use in the trie
  uint32_t field_padding[FieldPaddingInU32];
                                        // Space for adding later fields
  uint32_t comment_length;              // Length of comment to follow
  int8_t comment[CommentLength];        // Comment on data
  uint32_t padding[];
};

template<class PTYPE> struct FreeListMember
{
  PTYPE next;
};

template<class CTYPE,class PTYPE,unsigned int a_size> union TrieNodeUnion
{
  TrieNodeData<CTYPE,PTYPE,a_size> trie_node_data;
  FreeListMember<PTYPE> free_node;
};

#endif
