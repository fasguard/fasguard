#ifndef ABSTRACT_TRIE_NODE_HH
#define ABSTRACT_TRIE_NODE_HH
#include <map>
#include <string>
#include <vector>
#include <stack>
#include <boost/shared_ptr.hpp>
#include <boost/log/trivial.hpp>

class DistanceMetric;
class AbstractTrieNodeFactory;

/**
 * This abstract class defines the contract for TrieNode implementations both
 * for in-memory and disk based representations.
 */
class AbstractTrieNode
{
public:
  /**
   * Constructor.
   * @param atnf This is the AbstractTrieNodeFactory that produces new
   *    nodes for this trie.  It is either a disk trie factory or a memory
   *    trie factory.
   */
  AbstractTrieNode(AbstractTrieNodeFactory &atnf);
  /**
   * Default destructor.
   */
  virtual ~AbstractTrieNode()
  {}
  /**
   * Insert the next char of the string which might necessitate adding a new
   * node.  If a new node is added, a pointer to it is returned.
   * @param c Character to add.
   * @param end_string This character is an end of string.
   * @param inc_num_insertions Bump up the number of insertions for this char
   *    by this amount.  The default is 1.
   * @return Pointer to new node if added, or existing node.  Returns NULL
   *    node in case of error.
   */
  boost::shared_ptr<AbstractTrieNode> insertChar(unsigned int c,bool end_string,
                                               unsigned int inc_num_insertions
                                               = 1);
  /**
   * Next character to be matched, returning a pointer to the next node if
   * the char matches, NULL otherwise.  Also tells if this char terminated a
   * string.
   * @param c Next char to match
   * @param end_string Returns true if this is the end character of a string,
   *    false otherwise.
   * @param err_flag True if error has occured, false otherwise.
   * @return Pointer to next node or NULL if there are no other nodes.
   */
  boost::shared_ptr<AbstractTrieNode> matchChar(unsigned int c,bool &end_string,
                                              bool &err_flag)
    const;
  /**
   * Simple diagnostic print for given node.
   * @param How many tabs to indent this entry.
   */
  virtual void print(int indent) = 0;
  /**
   * This method adds itself to a count variable and then invokes count on all
   * its children.
   * @param count Variable in which to accumulate a count.
   * @return True if successful, false if error.
   */
  bool countNodes(unsigned int &count) const;

  /**
   * This method recursively builds up a list of prefixes of a given depth.
   * They are added to a map whose value is the number of occurences in of the
   * terminal node.
   * @param result_map Map with prefixes of length depth as keys and number
   *    of instances as values.
   * @param depth Requested depth.
   * @param cur_depth Current depth.
   * @param cur_prefix Prefix to current depth.
   */
  void prefixesAtDepth(std::map<std::string,unsigned int> &result_map,
                       int depth,int cur_depth,std::string cur_prefix);
  /**
   * This method recursively clears all m_end_string flags that are contained
   * in the decendants of the other node.
   * @param other_node The root of the other subtree which contains strings to
   *    erase.
   * @return True if successful, false if failure.
   */
  bool eraseEndString(const AbstractTrieNode &other_node);
  /**
   * This method finds the first node on a subtree that has the m_end_string
   * flag set and clears the m_end_string flag for all its descendants.
   * @param end_string_seen True if the m_end_string flag has been seen in an
   *    ancestor.
   */
  void keepFirstEndString(bool end_string_seen);
  /**
   * This method finds the last node on a subtree that has the m_end_string
   * flag set and clears the m_end_string flag for all its ancestors.
   * @param last_end_string The previous ancestor SignatureTrieNode that
   *    was an end of string.  Can be NULL.
   * @return True if successful, false if error.
   */
  bool keepLastEndString(AbstractTrieNode *last_end_string);
  /**
   * This method recursively goes down all child branches and tags them for
   * deletion for all nodes after the last end of string on each branch.
   * @return True if successful, false if error.
   */
  bool trimBranchesAfterEndString();
  /**
   * This method extracts all strings in the subtree of the current node into
   * a vector.
   * @param string_list Found strings will be added to this list.
   * @param cur_string The string we're working on now.
   * @return True if successful, false if error.
   */
  bool getAllStrings(std::vector<std::string> &string_list,
                     std::string cur_string);
  /**
   * Method to delete all nodes marked for deletion.
   * @return True if no errors, false otherwise.
   */
  bool cleanup();
  /**
   * This method returns whether or not this node is an end of string
   * @return 'true' if this node is an end of string, 'false' otherwise
   */
  bool isWord() const;
  /**
   * This method returns the occurrence counter for this node
   * @return Occurrence counter for this node
   */
  unsigned int getNumInsertions() const;
  /**
   * This method recursively produces a trie which contains only the strings
   * that are in both the current and other tries.
   * @param other The other node which is the root of a subtree with which we
   *    intersect.
   * @param result A reference to the current node of the result trie.
   * @return True if no error, false error.
   */
  bool intersectStrings(const AbstractTrieNode &other,
                        AbstractTrieNode &result);
  /**
   * This method recursively produces a trie which contains all the strings
   * that are either in the current or the other trie.
   * @param cur A node in the first subtrie.
   * @param other The other node which is the root of a subtree with which we
   *    are forming the union.
   * @param result A reference to the current node of the result trie.
   * @return True if no error, false if error.
   */
  static bool unionStrings(boost::shared_ptr<AbstractTrieNode> cur,
                           boost::shared_ptr<AbstractTrieNode> other,
                           boost::shared_ptr<AbstractTrieNode> result);
  /**
   * This method recursively produces a trie which contains all the strings
   * that are in either the current or other trie.
   * @param other The other node which is the root of a subtree with which we
   *    intersect.
   * @param result A reference to the current node of the result trie.
   * @return True if error, false if no error.
   */
  bool unionStrings(const AbstractTrieNode &other,
                    AbstractTrieNode &result);
  /**
   * Recursively compute the distance of the subtree's starting at 2 nodes
   * NOTE: The following cases are possible:
   *  1) Both stn1 and stn2 are non-NULL
   *  2) stn1 is NULL and stn2 is non-NULL
   *  3) stn1 is non-NULL and stn2 is NULL
   * @param stn1 Pointer to first node
   * @param stn2 Pointer to second node
   * @param num_strings1 Number of strings in trie for stn1
   * @param num_strings2 Number of strings in trie for stn2
   * @param dm Distance metric to use
   */
  static void distance(const AbstractTrieNode* stn1,
                       const AbstractTrieNode* stn2,
                       unsigned int       num_strings1,
                       unsigned int       num_strings2,
                       DistanceMetric& dm);
  /**
   * Recursive equality operation.  Checks all descendants.
   * @param other Other node against which to check.
   * @return True if equal, false otherwise.
   */
  bool operator==(const AbstractTrieNode &other) const;
  /**
   * Get a const pointer to the array of child nodes
   * @return const pointer to the array of child nodes
   */
  const AbstractTrieNode* const* getChildArray() const;
  /**
   * Get accessor for leaf flag (is this node a leaf?).
   * @return True if this is a leaf, false if not.
   */
  virtual bool getLeafFlag() const = 0;
  /**
   * Set accessor for leaf flag.
   * @param flag True if this node is now a leaf, false if not.
   */
  virtual void setLeafFlag(bool leaf_flag) = 0;
  /**
   * Get accessor for end string flag which indicates that the character
   * associated with this node is the end of a string.
   * @return True if this node is the end of a string, false if not.
   */
  virtual bool getEndStringFlag() const = 0;
  /**
   * Set accessor for end string flag.
   * @param flag True if this node will be the end of a string, false if not.
   */
  virtual void setEndStringFlag(bool end_string_flag) = 0;
  /**
   * Get accessor for cleanup flag that marks node for erasure.
   * @return True if this nod is to be erased, false otherwise.
   */
  virtual bool getCleanupFlag() const = 0;
  /**
   * Set accessor for cleanup flag that marks node for erasure.
   * @param cleanup_flag If this is true, node will be marked for eventual
   *    erasure.
   */
  virtual void setCleanupFlag(bool cleanup_flag) = 0;
  /**
   * Get accessor for number of children of this node.
   * @return Number of children of this node.
   */
  virtual uint16_t getNumChildren() const = 0;
  /**
   * Set accessor for number of children of this node.
   * @param num_children Number of children to set.
   */
  virtual void setNumChildren(uint16_t num_children) = 0;
  /**
   * Get accessor to retrieve the pointer index for the node corresponding
   * to a particular character.
   * @param c Character to look up.
   * @param err_flag Reference parameter to indicate error.
   * @return Pointer index corresponding to input flag.
   */
  virtual uint64_t getChildIndex(unsigned int c,bool &err_flag) const = 0;
  /**
   * Set accessor to set the pointer index for the node corresponding
   * to a particular character.
   * @param c Character to insert.
   * @param next_index Index of node that corresponds to c character.
   * @return True if successful, false if not.
   */
  virtual bool setChildIndex(unsigned int c,uint64_t next_index) = 0;
  /**
   * Get accessor to retrieve the character that pointed to this node
   * from its parent.
   * @return This node's character.
   */
  virtual unsigned int getMyChar() const = 0;
  /**
   * Set accessor to set the character that pointed to this node
   * from its parent.
   * @param c Character to set.
   */
  virtual void setMyChar(unsigned int c) = 0;
  /**
   * Retrieve size of alphabet which is also the number of elements in the
   * array of references to the next nodes.
   * @return Number of characters in the alphabet.
   */
  virtual unsigned int getAlphabetSize() const = 0;
protected:
  bool branchTrimmer(std::stack<boost::shared_ptr<AbstractTrieNode> > node_stack);
  AbstractTrieNodeFactory &m_atnf;
};
#endif
