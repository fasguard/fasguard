#ifndef LOCAL_ALIGNMENT_HH
#define LOCAL_ALIGNMENT_HH
#include <boost/python/module.hpp>
#include <boost/python/def.hpp>
#include <boost/python.hpp>
#include <string>
#include <vector>
#include <set>
#include <string>
#include <map>

/**
 * Result object containing fields for max_val, max_i, max_j, substring_x
 * and substring_y. There are more than one entry only if multiple scores have
 * the same value.
 */
class LAResult
{
public:
  LAResult(int max_val, int max_i, int max_j, std::string substring_x,
           std::string substring_y);
  LAResult();
  ~LAResult();
  int getMaxVal() const
  {
    return m_max_val;
  }
  std::string getSubstringX() const
  {
    return m_substring_x;
  }
  std::string getSubstringY() const
  {
    return m_substring_y;
  }
private:
int m_max_val;
int m_max_i;
int m_max_j;
std::string m_substring_x;
std::string m_substring_y;
};
/**
 * This class takes two strings and finds a substring of each that has the
 * highest alignment score.
 * The algorithme used is from "An Introduction to Bioinformatics Algorithms" by
 * Neil C. Jones and Pavel A. Pevzner.
 */
class LocalAlignment
{
public:
  /**
   * Constructor.
   * @param properties Properties dictionary passed down by Python code.
   *    number means unlimited depth.
   * @param bin_flag True if the input strings are binary, false if they are
   *    lower case a-z.
   */
  LocalAlignment(boost::python::dict properties, bool bin_flag);
  /**
   * Calculate the scores for each element of the alignment grid (see Sec 6.4
   * of Jones and Pevzner. Then, find the section of the transition graph where
   * the score is maximal.
   * @param string_x First string for running local alignment and X-coord for
   *    alignment grid.
   * @param string_y Second string for running local alignment and Y-coord for
   *    alignment grid.
   * @return LAResult object.
   */
  std::vector<LAResult>
  findMaxScore(std::string string_x, std::string string_y);
protected:
  /**
   * The scoring matrix which provides weights for insertions, deletions and
   * substitutions is input either from an external file or is given a default
   * value. The format for the input file is:
   *
   * ins 255 -1
   * del 84 -1
   * sub 37 72 1
   */
  void initScoringMatrix();

  /**
   * Method for extracting the two subtring from the original string where the
   * match is maximal.
   *
   * @param x_string First input string.
   * @param y_string Second input string.
   * @param i I location of current location on path.
   * @param j J location of current location on path.
   * @param a_grid Alignment grid reference.
   * @param p_grid Path grid reference
   * @param x_result Reference to x result string. Starts empty.
   * @param y_result_ref Reference to y result string. Starts empty.
   */

  void locAlignSubSeq(const std::string &x_string, const std::string &y_string,
                      int i, int j,
                      std::map<unsigned int,std::map<unsigned int,int> >
                      &a_grid,
                      std::map<unsigned int,std::map<unsigned int,std::string> >
                      &p_grid,
                      std::string &x_result,
                      std::string &y_result);
  std::map<unsigned int,std::map<unsigned int,std::string> > B;

  boost::python::dict m_properties;
  bool m_bin_flag;
  std::map<unsigned char,int> m_insert_table;
  std::map<unsigned char,int> m_delete_table;
  std::map<unsigned char, std::map<unsigned char, int> > m_substitute_table;
};
#endif
