#include <string>
#include <vector>
#include <set>
#include <string>
#include <map>

/**
 * This class takes a list of similar string samples and generates a regular
 * expression from it.
 *
 * We produce a regex which matches only the common substrings in all the
 * samples with appropriate dot-stars in between. We use the Longest Common
 * Substring (LCSS) algorithm between all pairs of strings. We take the
 * shortest match and make sure that it is found in all the other strings. If
 * it is, we cut it out of all the strings, leaving all the strings with a
 * before and after portion. We perform the same operations on the before and
 * after parts and then glue the pieces together with dot-stars.
 */
class RegexExtractorLCSS
{
public:
  /**
   * Constructor.
   * @param string_sample_list List of strings from which the regex will be
   *    generated.
   */
  RegexExtractorLCSS(std::vector<std::string> &string_sample_list);
  /**
   * Destructor.
   */
  ~RegexExtractorLCSS();

  /**
   * Recursive routine for finding sequences of matched regions common to all
   * samples.
   *
   * @param current_strings Strings in which we look for common matches.
   * @return List of common string sections in order
   */

  std::vector<std::string>
  findMatchSegmentSequence(std::vector<std::string> &current_strings);
  std::string lcss(std::string s1, std::string s2);
private:
  std::vector<std::string> m_string_sample_list;
};

const int REPETITION = 1000000;
