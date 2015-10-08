#ifndef TRIE_HH
#define TRIE_HH
#include <map>
#include <vector>
#include <boost/shared_ptr.hpp>
#include <boost/log/trivial.hpp>
#include "AbstractTrieNode.h"
#include "AbstractTrieNodeFactory.h"


/**
 * This class contains a trie designed for holding and extracting signatures.
 * It allows for a number of specialized operations, including providing a
 * long string and having all its substrings inserted as strings and also an
 * operation in which all the strings in one SignatureTrie are removed from
 * the other signature trie.
 */
class Trie
{
public:
  /**
   * Constructor.
   */
  Trie(boost::shared_ptr<AbstractTrieNodeFactory> atnf);
  /**
   * Destructor.
   */
  ~Trie();
  /**
   * Insert a single string.
   * @param str The string to insert, which may contain any byte pattern.
   * @param length Length of insertion string.
   * @return True if success, false if error.
   */
  bool insertString(const char *str,unsigned int length);
  /**
   * Inserts a string and all its prefixes, e.g. "abc" gives "a","bc" and "abc".
   * @param str The string to insert, with all its prefixes, which may contain
   *    any byte pattern.
   * @param length Length of insertion string.
   * @return True if success, false if error.
   */
  bool insertPrefixes(const char *str,unsigned int length);
  /**
   * Insert all possible contiguous substrings of a given string, e.g.if the
   * string is "abc", "a","b","c","ab","bc" and "abc" are inserted.
   * If depth is greater than zero, the longest strings are limited to length
   * depth.
   * @param str The master string from which all substrings are extracted.
   * @param length Length of master string.
   * @param depth The longest allowed string in the trie.
   * @return True if success, false if error.
   */
  bool insertAllSubstrings(const char *str,unsigned int length,
                           unsigned int depth);
  /**
   * Determines if the given string is found in the current trie.
   * @param string String to look for.
   * @param length Length of string.
   * @param err_flag True if error has occured.
   * @return True if string found, false if not.
   */
  bool matchString(unsigned char *str,unsigned int length,
                   bool &err_flag) const;
  /**
   * Determines if the given string is found in the current trie.
   * @param string String to look for.
   * @param err_flag True if error has occured.
   * @return True if string found, false if not.
   */
  bool matchString(const std::string &str,bool &err_flag) const;
  /**
   * This method produces a trie which contains only the strings that are in
   * both the current and other tries.  The number of insertions counter
   * for surviving nodes is equal to the sum of this and other.
   * @param other The other trie with which we intersect.
   * @param result The empty trie into which we place the result.
   * @return True if success, false if error.
   */
  bool intersectStrings(const Trie &other,Trie &result);
  /**
   * This method produces a trie which contains all the strings that are either
   * in the current or other trie.
   * @param other The other trie with which we form a union.
   * @param result An empty trie into which we place a result.
   */
  bool unionStrings(const Trie &other,Trie &result);
  /**
   * All strings found in parameter Trie are removed from current
   * trie.
   * @param other Trie containing all strings to remove from current
   *    trie.
   */
  void subtractStrings(const Trie &other);
  /**
   * We produce a trie in which we cut the current trie at the first end of
   * string on each branch, thus giving us the shortest prefix string.
   */
  void shortestPrefixString();
  /**
   * We produce a trie in which we remove all the substrings less than the
   * longest in a subtree.
   */
  void longestPrefixString();
  /**
   * Given a list of strings, we subtract the longest suffix from each string
   * that is found in the current Trie.
   * @param input_strings List of input strings to have suffix trimming
   *    performed on them.
   * @param result_strings Empty list of result strings that have been trimmed.
   * @return True if successful, false otherwise.
   */
  bool trimStringSuffixes(const std::vector<std::string> &input_strings,
                          std::vector<std::string> &result_strings);
  /**
   * Fills a map with all the prefixes in the trie of exactly length depth,
   * and the value of the map is the number of occurances.
   * @param result_map Map with prefixes of length depth as keys and number
   *    of instances as values.
   * @param depth Requested depth.
   */
  void prefixesAtDepth(std::map<std::string,unsigned int> &result_map,
                       int depth);
  /**
   * Retrieves total number of nodes in trie.
   * @param err_flag - True if error has occured.
   * @return Number of nodes in trie.
   */
  unsigned int getNumNodes(bool &err_flag) const;
  /**
   * Simple, primitive print function for debugging.
   */
  void print();
  /**
   * Extracts all strings in this trie into a vector.
   * @param string_list An empty vector that will be filled with all strings
   *    in this trie.
   * @return True if successful, false if error occurs.
   */
  bool getAllStrings(std::vector<std::string> &string_list);
  /**
   * Equality operator.  Recursively checks for m_root_node equality which
   * checks its decendants.
   * @param other Other Trie to compare to.
   * @return True if equal, false otherwise.
   */
  bool operator==(const Trie &other) const;
  /**
   * Trie inequality operator
   * @param st Reference to  trie object
   * @return 'true' if 'other' is not equal to this object, 'false' otherwise
   */
  bool operator!=(const Trie& other) const;
  /**
   * Get the number of strings that were used to construct this trie. Note
   * that if a string was inserted multiple times, each insertion contributes
   * to the sum returned by this method.
   * @return Total number of strings that were used to construct this true
   */
  unsigned int getNumInsertions() const;
  /**
   * This method determines if the AbstractTrieNodeFactory believes that the
   * Trie is full.
   * @return True if the trie is full, false if there is room.
   */
  bool trieFullP() const;
  static unsigned int totalTrieObjs();
  const unsigned int getTryObjId() const;
private:
  boost::shared_ptr<AbstractTrieNode> m_root_node;
  boost::shared_ptr<AbstractTrieNodeFactory> m_atnf;
  static unsigned int obj_count;
  unsigned int try_obj_id;

};
#endif
