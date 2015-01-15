#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <algorithm>
#include <stdlib.h>

#include "LocalAlignment.hh"

LAResult::LAResult(int max_val, int max_i, int max_j,
                   std::string substring_x,
                   std::string substring_y) :
  m_max_val(max_val),m_max_i(max_i),
  m_max_j(max_j),
  m_substring_x(substring_x),
  m_substring_y(substring_y)
{}

LAResult::LAResult() :
  m_max_val(0),m_max_i(0),
  m_max_j(0),
  m_substring_x(""),
  m_substring_y("")
{}

LAResult::~LAResult()
{}

LocalAlignment::LocalAlignment(boost::python::dict properties, bool bin_flag) :
  m_properties(properties),m_bin_flag(bin_flag)
{
  initScoringMatrix();
}

void
LocalAlignment::initScoringMatrix()
{
  unsigned int c_start, c_end;

  if(m_bin_flag)
    {
      c_start = 0;
      c_end = 255;
    }
  else
    {
      c_start = 'a';
      c_end = 'z';
    }

  std::string scoring_engine_file;
  if(m_properties.has_key("LocalAlignment.ScoringEngineFile"))
    {
      scoring_engine_file =
        boost::python::extract<std::string>(
                                            m_properties
                                            ["LocalAlignment.ScoringEngineFile"]);
      BOOST_LOG_TRIVIAL(error)   <<
        "LocalAlignment::initScoringMatrix currently does nothing with " <<
        "LocalAlignment.ScoringEngineFile" <<
        std::endl;
    }
  else
    {
      for(unsigned int i = c_start; i <= c_end; i++)
        {
          // BOOST_LOG_TRIVIAL(debug)   <<
          //   "outer loop i=" << int(i) <<
          //    std::endl;

          m_insert_table[i] = -1;
          m_delete_table[i] = -1;
          for(unsigned int j = c_start; j <= c_end; j++)
            {
              // BOOST_LOG_TRIVIAL(debug)   <<
              //        "inner loop: i=" << int(i) << " j=" << int(j) <<
              //        std::endl;

              if(i == j)
                {
                  m_substitute_table[i][j] = 1;
                }
              else
                {
                  m_substitute_table[i][j] = -1;
                }
              if(j == c_end)
                break;
            }
          if(i == c_end)
            break;
        }
    }


}


std::vector<LAResult>
LocalAlignment::findMaxScore(std::string string_x, std::string string_y)
{
  std::map<unsigned int,std::map<unsigned int,int> > S;
  std::map<unsigned int,std::map<unsigned int,std::string> > B;

  BOOST_LOG_TRIVIAL(debug)   <<
    "At start of findMaxScore" << std::endl;

  for(unsigned int i=0;i<=string_x.length();i++)
    {
      S[i][0] = 0;
    }

  for(unsigned int j=1;j<=string_y.length();j++)
    {
      // BOOST_LOG_TRIVIAL(debug)   <<
      //        "At -1" << std::endl;
      S[0][j] = 0;
      // BOOST_LOG_TRIVIAL(debug)   <<
      //        "At 0" << std::endl;
      for(unsigned int i=1;i<=string_x.length();i++)
        {
          std::vector<int> tmp;
          // BOOST_LOG_TRIVIAL(debug)   <<
          //   "At 1, i = " << i << " of " << string_x.length() << std::endl;

          tmp.push_back(0);
          tmp.push_back(S[i-1][j-1] + m_substitute_table[string_x[i-1]]
                        [string_y[j-1]]);
          tmp.push_back(S[i-1][j] + m_delete_table[string_x[i-1]]);
          tmp.push_back(S[i][j-1] + m_insert_table[string_y[j-1]]);
          S[i][j] = *std::max_element(tmp.begin(),tmp.end());

          // BOOST_LOG_TRIVIAL(debug)   <<
          //   "At 2" << std::endl;

          if(S[i][j] == tmp[2])
            {
              B[i][j] = "N";
            }
          else if(S[i][j] == tmp[3])
            {
              B[i][j] = "W";
            }
          else if(S[i][j] == tmp[1])
            {
              B[i][j] = "NW";
            }
          else if(S[i][j] == tmp[0])
            {
              B[i][j] = "Z";
            }
          else
            {
              BOOST_LOG_TRIVIAL(error)   <<
                "Error, S " << i << " " << j << " is " << S[i][j] << std::endl;
              exit(-1);
            }

          // BOOST_LOG_TRIVIAL(error)   <<
          //   "At 3" << std::endl;

        }
    }
  BOOST_LOG_TRIVIAL(debug)   <<
    "At end of findMaxScore" << std::endl;

  // Find max S value and its location

  int cur_max = -100;

  for(int i = 0; i<S.size();i++)
    {
      for(int j = 0; j<S[i].size(); j++)
        {
          if(S[i][j] >= cur_max)
            {
              cur_max = S[i][j];
            }
        }
    }

  std::vector<LAResult> result_list;

  std::vector<int> max_val;
  std::vector<int> max_i;
  std::vector<int> max_j;

  for(int i=0;i<S.size();i++)
    {
      for(int j=0;j<S[i].size();j++)
        {
          if(S[i][j] == cur_max)
            {
              max_i.push_back(i);
              max_j.push_back(j);
              std::string sub_string_x("");
              std::string sub_string_y("");
              locAlignSubSeq(string_x,string_y,i,j,S,B,sub_string_x,
                             sub_string_y);
              result_list.push_back(LAResult(S[i][j],i,j,sub_string_x,
                                             sub_string_y));
            }
        }

    }

  return result_list;
}

void
LocalAlignment::locAlignSubSeq(const std::string &x_string,
                               const std::string &y_string,
                               int i, int j,
                               std::map<unsigned int,std::map<unsigned int,
                               int> >
                               &a_grid,
                               std::map<unsigned int,std::map<unsigned int,
                               std::string> >
                               &p_grid,
                               std::string &x_result,
                               std::string &y_result)
{
  std::string b = p_grid[i][j];

  if((a_grid[i][j] == 0) || (p_grid[i][j] == "Z"))
    {
      return;
    }
  else if(b == "NW")
    {
      locAlignSubSeq(x_string,y_string,i-1,j-1,a_grid,p_grid,x_result,y_result);
      x_result.append(x_string.substr(i-1,1));
      y_result.append(y_string.substr(j-1,1));
    }
  else if(b == "N")
    {
      locAlignSubSeq(x_string,y_string,i-1,j,a_grid,p_grid,x_result,y_result);
    }
  else if(b == "W")
    {
       locAlignSubSeq(x_string,y_string,i,j-1,a_grid,p_grid,x_result,y_result);
    }
  else
    {
      BOOST_LOG_TRIVIAL(error)   <<
        "B " << i << j << " is " << b << std::endl;
      exit(-1);
    }
}
