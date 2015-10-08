#ifndef DENDROGRAM_HH
#define DENDROGRAM_HH
#include <boost/python/module.hpp>
#include <boost/python/def.hpp>
#include <boost/python.hpp>
#include <string>
#include <vector>
#include <set>
#include <string>
#include <map>
#include <memory>
#include "tree.hh"
#include "LocalAlignment.hh"

/**
 * Each tree node has two entries: max_score which is the maximum score for all
 * members of the new level and md5_set which is a set of the MD5s of the
 * strings in this cluster.
 */
class TreeNode
{
public:
  /**
   * Constructor.
   * @param max_score maximum score for all members of the new level.
   * @param md5_set set of the MD5s of the strings in this cluster.
   */
  TreeNode(int max_score, std::set<std::string> md5_set);
  TreeNode();
  ~TreeNode();
  std::set<std::string> &
  getMd5Set()
  {
    return m_md5_set;
  }
  int getMaxScore() const
  {
    return m_max_score;
  }
private:
  int m_max_score;
  std::set<std::string> m_md5_set;
};

/**
 * Given a list of strings, we construct a dendrogram based on local alignment
 * distances.

 * First, we contruct a distance matrix between strings. We then recursively
 * find the two clusters with the largest local alignment distance between
 * members and merge them. This continues until only one cluster remain.
 */
class Dendrogram
{
public:
  /**
   * Constructor.
   * @param properties Properties dictionary passed down by Python code.
   *    number means unlimited depth.
   * @param string_list Vector of strings from which the dendrogram will be
   *    constructed (typically, a set of packet contents).
   */
  Dendrogram(boost::python::dict properties,
             const std::vector<std::string> &string_list);
  /**
   * Destructor.
   */
  ~Dendrogram();
  /**
   * Use LocalAlignment to calculate the edit distance between strings using
   * local alignment.
   */
  void makeDistMtrx();

  /**
   * We start with N clusters. We merge the closest two clusters in every pass,
   * where the inter-cluster distance is the max edit distance of any two node
   * in the two groups. The value at each tree node is a reference to a hash
   * which has two entries: MAX_SCORE which is the maximum score for all
   * members of the new level and MD5_SET which is a hash of the MD5s of the
   * strings in this cluster.
   *
   * @return A reference to the dendrogram tree.
   */
  boost::shared_ptr<tree<TreeNode> > makeDendrogram();

  /**
   * Given two sets of MD5s of strings, we find a pair consisting of a string
   * from one and a string from the other that have a maximal edit score. We
   * return that score.
   *
   * @param set1 First set of MD5s for strings.
   * @param set2 Second set of MD5s for strings
   * @return Max edit score.
   */
  int getMaxEditDistVal(const std::set<std::string> &set1,
                        const std::set<std::string> &set2);

  /**
   * Setter method for m_dendrogram_tree property which is the tree representing
   * the dendrogram where the leaves are specific samples and each level up
   * involves the merging of the elements below it.
   *
   * @param dendrogram_tree A completed dendrogram tree to store in
   *    the m_dendrogram_tree member.
   */
  void
  setDendrogramTree(boost::shared_ptr<tree<TreeNode> > dendrogram_tree)
  {
    m_dendrogram_tree = dendrogram_tree;
  }
  /**
   * Given the dendrogram tree, we find the first pair of sets that are above a
   * certain percentage threshold in edit distance apart. We start at the
   * deepest leaves, and as we go up each level see if the percentage change is
   * greater than a given threshold. If it is, we declare the two groups
   * directly below the threshold jump to be its own string set. This pair is
   * returned.
   *
   * @return Pair of string sets.
   */
  std::vector<std::set<std::string> > findDisjointStringSets();

  /**
   * Returns a list of the leaves of the dendrogram tree. We produce this be
   * traversing the tree and collecting the nodes.
   *
   * @return Reference to list of leaf nodes of the dendrogram tree.
   */
  std::vector<std::string> getDTreeLeaves();

  /**
   * Starting at a leaf node, move back up until a node is reached that is more
   * than the percent threshold above its predecessors and then return it.
   * Otherwise, the tree root node is returned.
   * @param leaf_it An iterator referring to a tree node with no children.
   * @param tr A reference to the dendrogram tree that we're handling.
   * @param percent_thresh The percentage threshold we're looking for.
   * @param ex_node_it A return value containing an iterator to a node where
   *    the threshold is exceeded.
   * @return True if a transition is found where the threshold is exceeded,
   *    false otherwise.
   */
  bool
  backup2Thresh(tree<TreeNode>::iterator &leaf_it,tree<TreeNode> &tr,
                double percent_thresh, tree<TreeNode>::iterator &ex_node_it);

  /**
   * Given a list of MD5s for various strings, for every pair on the list we
   * produce the pair of substrings produced by the local alignment algorithm
   * and then return all these strings.
   *
   * @param md5_list A list of the MD5s for a particular cluster.
   * @return A list of subsequences common to each of the pairs of strings.
   */
  std::vector<std::string>
  gatherSubsequences(std::set<std::string> &md5_list);
protected:
  boost::python::dict m_properties;
  const std::vector<std::string> &m_string_list;
  std::map<std::string, std::map<std::string, std::vector<LAResult> > >
  m_matrix;
  boost::shared_ptr<tree<TreeNode> > m_dendrogram_tree;
};

/**
 * Some useful constants.
 */

const int KeyLength = 7;
#endif
