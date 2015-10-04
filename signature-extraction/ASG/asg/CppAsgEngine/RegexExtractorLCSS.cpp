#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <stdlib.h>
#include "RegexExtractorLCSS.hh"

RegexExtractorLCSS::RegexExtractorLCSS(std::vector<std::string> &
                                       string_sample_list) :
  m_string_sample_list(string_sample_list)
{
}

RegexExtractorLCSS::~RegexExtractorLCSS()
{
}

std::vector<std::string>
RegexExtractorLCSS::findMatchSegmentSequence(std::vector<std::string>
                                             &current_strings)
{
  // First, find shortest LCSS between a pair
  std::string shortest_string(REPETITION,'x');

  std::vector<std::string> reduce_strings = current_strings;
  bool break_flag = true;
  while(1)
    {
      break_flag = true;
      // Find shortest "longest" string that is common between at least
      // two instances. If all instances are to have some common substring,
      // it must be contained in this string.
      std::vector<std::string> common_strings;
      for(int i=0;i<reduce_strings.size();i++)
        {
          for(int j=i+1;j<reduce_strings.size();j++)
            {
              // BOOST_LOG_TRIVIAL(debug)   << "In lcss loop: "<<
              //        i << "," << j << std::endl;
              std::string longest = lcss(reduce_strings[i],
                                         reduce_strings[j]);
              // BOOST_LOG_TRIVIAL(debug)   << "After lcss call "<<  std::endl;
              common_strings.push_back(longest);

              if(longest.size() < shortest_string.size())
                {
                  shortest_string = longest;
                }
            }
        }
          // If the new shortest string is still too long to match all the
          // instances, we reduce the list we search to only shorter common
          // substrings. If we keep reducing the lengths of the compared strings
          // in this fashion, we will get down to the "atomic" common string if
          // it exists.
      for(std::vector<std::string>::iterator str_it =
            current_strings.begin();str_it != current_strings.end();
          str_it++)
        {
          if((*str_it).find(shortest_string) == std::string::npos)
            {
              reduce_strings = common_strings;
              break_flag = false;
              break;
            }
        }

      if(break_flag)
        break;
    }
  if(shortest_string.size() >= REPETITION || shortest_string.size() == 0)
    {
      return std::vector<std::string>();
    }

  // We now divide all the strings into a list of elements that occur before
  // the common substring calculated above and a list of elements that occur
  // after it. We recurse on each list, ultimately producing a list of
  // regions that all samples have in common.

  std::vector<std::string> before;
  std::vector<std::string> after;

  for(std::vector<std::string>::iterator str_it =
        current_strings.begin();str_it != current_strings.end();
      str_it++)
    {
      std::size_t location = (*str_it).find(shortest_string);
      if(location  != std::string::npos)
        {
          if(location > 0)
            {
              before.push_back((*str_it).substr(location,
                                                shortest_string.length()));
            }
          if((*str_it).length() - location - shortest_string.length() >
             0)
            {
              after.push_back((*str_it).substr(location+
                                               shortest_string.length(),
                                               std::string::npos));
            }
        }
      else
        {
          BOOST_LOG_TRIVIAL(debug)   <<
            "Found no match for string of length " << (*str_it) << std::endl;
          exit(-1);
        }
    }
  std::vector<std::string> result;

  if(before.size() == current_strings.size())
    {
      std::vector<std::string> before_result =
        findMatchSegmentSequence(before);
      result.insert(result.end(),before_result.begin(),before_result.end());
    }
  result.push_back(shortest_string);
  if(after.size() == current_strings.size())
    {
      std::vector<std::string> after_result =
        findMatchSegmentSequence(after);
      result.insert(result.end(),after_result.begin(),after_result.end());

    }
  return result;
}

std::string
RegexExtractorLCSS::lcss(std::string s1, std::string s2)
{
  std::vector<std::vector<int> > m(1+s1.size(),
                                   std::vector<int>(1+s2.size(),0));
  // BOOST_LOG_TRIVIAL(debug)   << "Size of outer vector: "
  //                         << m.size() << std::endl;
  // BOOST_LOG_TRIVIAL(debug)   << "Size of inner vector: "
  //                         << m[0].size() << std::endl;



  int longest = 0;
  int x_longest = 0;
  for(int x = 1;x<1+s1.size();x++)
    {
      for(int y = 1;y<1+s2.size();y++)
        {
          if(s1[x-1] == s2[y-1])
            {
              m[x][y] = m[x-1][y-1] + 1;
              if(m[x][y] > longest)
                {
                  longest = m[x][y];
                  x_longest = x;
                }
            }
          else
            {
              m[x][y] = 0;
            }
        }
    }
  return s1.substr(x_longest - longest,longest - 1);
}
