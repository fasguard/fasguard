#include <iostream>
#include "Trie.h"
#include "TrieNodeFactorySpecialization.h"

#undef DEBUG_ST
using namespace std;

unsigned int Trie::obj_count = 0;
Trie::Trie(boost::shared_ptr<AbstractTrieNodeFactory> atnf) :
  m_root_node(atnf->retrieveNode(0)),m_atnf(atnf)
{
    ++obj_count;
    try_obj_id = obj_count;
}

Trie::~Trie()
{
}

bool
Trie::insertString(const char *str,unsigned int length)
{
  if(length == 0)
    return true;
  boost::shared_ptr<AbstractTrieNode> stn_ptr = m_root_node;
  for(register unsigned int i=0;i<length-1;i++)
    {
      stn_ptr = stn_ptr->insertChar((unsigned char)str[i],false);
      if(!stn_ptr)
        {
          BOOST_LOG_TRIVIAL(error)
                   << "insertString failed"
                   << endl;
          return false;
        }
    }
  stn_ptr = stn_ptr->insertChar((unsigned char)str[length-1],true);
  if(!stn_ptr)
    {
      BOOST_LOG_TRIVIAL(error)
               << "insertString failed"
               << endl;
      return false;
    }
  return true;
}

bool
Trie::insertPrefixes(const char *str,unsigned int length)
{
  boost::shared_ptr<AbstractTrieNode> stn_ptr = m_root_node;
  for(register unsigned int i=0;i<length;i++)
    {
      stn_ptr = stn_ptr->insertChar(static_cast<unsigned char>(str[i]),true,
                                    length-i);
      if(!stn_ptr)
        {
          BOOST_LOG_TRIVIAL(error)
                   << "insertChar failed in insertPrefixes"
                   << endl;
          return false;
        }
    }
  return true;
}

bool
Trie::insertAllSubstrings(
                          const char*        str,
                          unsigned int length,
                          unsigned int depth)
{
  BOOST_LOG_TRIVIAL(debug)   << "Length: " << length <<
    " Depth: " << depth << std::endl;

  // According to Dan, depth=0 means that we should not modify the trie
  if(0 == depth)
  {
    return true;
  }

  // Depth<0 means that there is no "horizon" limitation. To achieve this
  // with respect to the algorithm below, all we need to do is set the depth
  // limitation equal to the total length of the given string. Also, if the
  // depth is greater than the string length, we can simplify things if we set
  // the depth to the length of the string.
  if((depth < 0) ||
     (depth > length))
  {
    depth = length;
  }

  // pointer to one byte beyond the last byte in the string
  register const char* const s_end = str + length;

  // number of actual characters remaining in the string
  // NOTE: We allocate this outside the loop for speed efficiency
  register unsigned int remaining = 0;

  // now let's iterate through the string and insert all prefixes for
  // each window (start to horizon)
  for( ; str != s_end ; ++str)
  {
    // number of actual characters remaining in the string
    remaining = static_cast<unsigned int>(s_end - str);

    // insert all the prefixes of the string from here to the end of this
    // window. Notice that we're careful to not run off the end of the string.
    if(!insertPrefixes(str, (remaining > depth) ? depth : remaining))
      return false;
  }
  return true;
}

void Trie::print()
{
  m_root_node->print(0);
}

unsigned int
Trie::getNumNodes(bool &err_flag) const
{
  unsigned int result = 0;
  err_flag = false;

  if(!m_root_node->countNodes(result))
    err_flag = true;
  return result;
}
#if 0
void
Trie::prefixesAtDepth(std::map<std::string,unsigned int> &result_map,
                               int depth)
{
  string null_string;
  m_root_node.prefixesAtDepth(result_map,depth,0,null_string);
}
#endif
void
Trie::subtractStrings(const Trie &other)
{
  // The algorithm for this method involves three steps:
  // 1) The end string flag is unset for every node in this trie that is set
  //    in the other trie.
  // 2) A second pass is made on this trie which marks for deletion all nodes
  //    after the last end of string node on a branch
  // 3) All nodes labeled for deletion are deleted

  BOOST_LOG_TRIVIAL(debug)
           << "Before eraseEndString"
           << endl;
#if 0
  m_root_node->print(0);
#endif
  m_root_node->eraseEndString(*other.m_root_node);
  BOOST_LOG_TRIVIAL(debug)
           << "Before trimBranchesAfterEndString"
           << endl;
#if 0
  m_root_node->print(0);
#endif

#if 0
  m_root_node->print(0);
#endif
#if 0
  m_root_node->cleanup();
#endif
}

#if 0
void
Trie::shortestPrefixString()
{
#if 0
  unsigned int count = 0;
  m_root_node.countNodes(count);
  cout << "At beginning of  shortestPrefixString, node count="
       << count << endl;
#endif
  m_root_node.keepFirstEndString(false);
  m_root_node.trimBranchesAfterEndString();
  m_root_node.cleanup();
#if 0
  count = 0;
  m_root_node.countNodes(count);
  cout << "At end of  shortestPrefixString, node count="
       << count << endl;
#endif
}
#endif
void
Trie::longestPrefixString()
{
  m_root_node->keepLastEndString(NULL);
#if 0
  m_root_node->trimBranchesAfterEndString();
  m_root_node->cleanup();
#endif
}
#if 0
void
Trie::getAllStrings(vector<string> &string_list)
{
  string empty_str;
  m_root_node.getAllStrings(string_list,empty_str);
}

void
Trie::intersectStrings(const Trie &other,
                                Trie &result)
{
  m_root_node.intersectStrings(other.m_root_node,
                               result.m_root_node);
  result.m_root_node.trimBranchesAfterEndString();
  result.m_root_node.cleanup();
}
#endif
bool
Trie::trimStringSuffixes(const vector<string> &input_strings,
                         vector<string> &result_strings)
{
  vector<string>::const_iterator cit = input_strings.begin();

  while(cit != input_strings.end())
    {
      int last_match = -1;
      for(register int i=(*cit).size()-1;i>=0;i--)
        {
          string suffix((*cit).substr(i));
          bool err_flag = false;
          if(matchString(suffix,err_flag))
            {
              last_match = i;
            }
          if(err_flag)
            {
              BOOST_LOG_TRIVIAL(error)
                       << "matchString error" << endl;
              return false;
            }
        }
      if(last_match > 0)
        {
          result_strings.push_back((*cit).substr(0,last_match));
        }
      else
        {
          result_strings.push_back(*cit);
        }
      cit++;
    }
  return true;
}

bool
Trie::matchString(const string &str,bool &err_flag) const
{
  err_flag = false;
  if(str.length() == 0)
    return true;

  boost::shared_ptr<AbstractTrieNode> cur_node = m_root_node;

  bool end_string = false;
  for(register unsigned int i=0;i<str.length()-1;i++)
    {
      cur_node =
        cur_node->matchChar(static_cast<unsigned char>(str[i]),end_string,
                            err_flag);
      if(err_flag)
        {
          BOOST_LOG_TRIVIAL(error)
                   << "Error in matchChar" << endl;
          return false;
        }
      if(!cur_node)
        {
          return false;
        }
    }

  cur_node =
    cur_node->matchChar(static_cast<unsigned char>(str[str.length()-1]),
                        end_string,err_flag);

  if(err_flag)
    {
      BOOST_LOG_TRIVIAL(error)
               << "Error in matchChar" << endl;
      return false;
    }
  if(!cur_node)
    return false;
  if(end_string)
    return true;
  else
    return false;
}

bool
Trie::intersectStrings(const Trie &other,
                       Trie &result)
{
  if(!m_root_node->intersectStrings(*other.m_root_node,
                                    *result.m_root_node))
    {
      BOOST_LOG_TRIVIAL(error)
               << "ERROR IN Trie::intersectStrings!!!" << endl;
      return false;
    }

  result.m_root_node->trimBranchesAfterEndString();
  result.m_root_node->cleanup();
  return true;
}

bool
Trie::unionStrings(const Trie &other,Trie &result)
{
  if(!AbstractTrieNode::unionStrings(m_root_node,other.m_root_node,
                                     result.m_root_node))
    {
      BOOST_LOG_TRIVIAL(error)
               << "ERROR IN Trie::unionStrings!!!" << endl;
      return false;
    }
  return true;
}

bool
Trie::getAllStrings(vector<string> &string_list)
{
  string empty_str;
  return m_root_node->getAllStrings(string_list,empty_str);
}

bool
Trie::trieFullP() const
{
   return m_atnf->getNumNodes() > m_atnf->maxNumNodes();
}
unsigned int
Trie::totalTrieObjs()
{
   return obj_count;
}
const unsigned int
Trie::getTryObjId() const
{
    return try_obj_id;
}
