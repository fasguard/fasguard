#include "SmlLrgSigExtrct.hh"

SmlLrgSigExtrct::SmlLrgSigExtrct(std::set<std::string> &in_strings) :
  m_in_strings(in_strings)
{
}

SmlLrgSigExtrct::~SmlLrgSigExtrct()
{}

boost::shared_ptr<std::set<std::string> >
SmlLrgSigExtrct::smallStringSet()
{
  std::set<std::string> candidates(m_in_strings.begin(),
                                   m_in_strings.end());

  boost::shared_ptr<std::set<std::string>> result(new std::set<std::string>());

  while(candidates.size() > 0)
    {
      // Find shortest string
      unsigned int min_length = (*candidates.begin()).length();
      std::set<std::string>::iterator s_it = candidates.begin();
      while(s_it != candidates.end())
        {
          unsigned int lgth = (*s_it).length();
          if(lgth < min_length)
            {
              min_length = lgth;
            }
          s_it++;
        }

      // Shortest are automatically part of result and are also removed from
      // candidates

      std::set<std::string> tmp_set;
      s_it = candidates.begin();
      while(s_it != candidates.end())
        {
          if((*s_it).length() == min_length)
            {
              (*result).insert(*s_it);
              tmp_set.insert(*s_it);
              candidates.erase(s_it);
            }
          s_it++;
        }

      // Check all candidates to see if tmp_set members are substrings and if
      // so, remove them

      std::set<std::string>::iterator t_it = tmp_set.begin();
      while(t_it != tmp_set.end())
        {
          std::set<std::string>::iterator c_it = candidates.begin();
          while(c_it != candidates.end())
            {
              if((*c_it).find(*t_it) != std::string::npos)
                {
                  // Small string found in larger string. Remove the larger
                  // string
                  candidates.erase(c_it);
                }
              c_it++;
            }
          t_it++;
        }

    }
  return result;
}
