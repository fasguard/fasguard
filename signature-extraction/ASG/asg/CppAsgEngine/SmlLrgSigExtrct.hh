#ifndef SML_SIG_EXTRCT_HH
#define SML_SIG_EXTRCT_HH
#include <boost/shared_ptr.hpp>
#include <string>
#include <set>

/**
 * Given a set of strings some of which are substrings of others, we produce a
 * set of strings that exclude all strings that are containing strings of other
 * strings or remove all substrings from the set, depending on method used.
 */
class SmlLrgSigExtrct
{
public:
  /**
   * Constructor.
   * @param in_strings Set of strings being input.
   */
  SmlLrgSigExtrct(std::set<std::string> &in_strings);
  /**
   * Destructor.
   */
  ~SmlLrgSigExtrct();
  /**
   * Find set of smallest contained strings.
   *
   * @return A pointer to the reduced set of strings.
   */
  boost::shared_ptr<std::set<std::string> > smallStringSet();
protected:
  std::set<std::string> &m_in_strings;
};
#endif
