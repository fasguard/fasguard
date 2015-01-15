#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <iostream>
#include <set>
#include <memory>
#include <cmath>
#include <stdlib.h>

#include "Dendrogram.hh"

TreeNode::TreeNode()
{}

TreeNode::TreeNode(int max_score, std::set<std::string> md5_set) :
  m_max_score(max_score),m_md5_set(md5_set)
{
}


TreeNode::~TreeNode()
{}

Dendrogram::Dendrogram(boost::python::dict properties,
                       const std::vector<std::string> &string_list) :
  m_properties(properties),m_string_list(string_list)
{
}

Dendrogram::~Dendrogram()
{}

void
Dendrogram::makeDistMtrx()
{
  std::vector<std::string>::const_iterator cit1 = m_string_list.begin();

  int i = 0;
  while(cit1 != m_string_list.end())
    {
      CryptoPP::MD5 hash1;
      byte digest1[ CryptoPP::MD5::DIGESTSIZE ];

      hash1.CalculateDigest( digest1, (const byte*) (*cit1).data(),
                             (*cit1).length() );

      CryptoPP::HexEncoder encoder1;
      std::string md5_1,md5_1_tmp;
      encoder1.Attach( new CryptoPP::StringSink( md5_1_tmp ) );
      encoder1.Put( digest1, sizeof(digest1) );
      encoder1.MessageEnd();

      md5_1 = md5_1_tmp.substr(0,KeyLength);
      BOOST_LOG_TRIVIAL(debug) << "md5_1: " << md5_1 << std::endl;

      std::vector<std::string>::const_iterator cit2 = m_string_list.begin();

      int j = 0;
      while(cit2 != m_string_list.end())
        {
          BOOST_LOG_TRIVIAL(debug) << "String " << i << "," << j <<  std::endl;

          CryptoPP::MD5 hash2;
          byte digest2[ CryptoPP::MD5::DIGESTSIZE ];

          hash2.CalculateDigest( digest2, (const byte*) (*cit2).data(),
                                 (*cit2).length() );

          CryptoPP::HexEncoder encoder2;
          std::string md5_2,md5_2_tmp;
          encoder2.Attach( new CryptoPP::StringSink( md5_2_tmp ) );
          encoder2.Put( digest2, sizeof(digest2) );
          encoder2.MessageEnd();
          md5_2 = md5_2_tmp.substr(0,KeyLength);
          BOOST_LOG_TRIVIAL(debug) << "md5_2: " << md5_2 << std::endl;

          LocalAlignment la(m_properties, true);

          int cmp = md5_1.compare(md5_2);

          if(cmp < 0)
            {
              // md5_1 < md5_2
              if((m_matrix.find(md5_1) == m_matrix.end()) ||
                 (m_matrix[md5_1].find(md5_2) == m_matrix[md5_1].end()))
                {
                  std::vector<LAResult> larslt = la.findMaxScore(*cit1,*cit2);
                  BOOST_LOG_TRIVIAL(debug)   <<
                    "After case -1 findMaxScore" << std::endl;
                  m_matrix[md5_1][md5_2] = larslt;
                }
            }
          else if(cmp > 0)
            {
              // md5_1 < md5_2
              if((m_matrix.find(md5_2) == m_matrix.end()) ||
                 (m_matrix[md5_2].find(md5_1) == m_matrix[md5_2].end()))
                {
                  std::vector<LAResult> larslt = la.findMaxScore(*cit2,*cit1);
                  BOOST_LOG_TRIVIAL(debug)   <<
                    "After case +1 findMaxScore" << std::endl;
                  m_matrix[md5_2][md5_1] = larslt;
                }
            }
          else
            {
              BOOST_LOG_TRIVIAL(debug)   <<
                md5_1 << " == " << md5_2 << std::endl;
            }
          j++;
          cit2++;
        }

      i++;
      cit1++;
    }
  BOOST_LOG_TRIVIAL(debug)   <<
    "After makeDistMtrx" << std::endl;

}

boost::shared_ptr<tree<TreeNode> >
Dendrogram::makeDendrogram()
{
  std::set<std::string> leaf_set;
  BOOST_LOG_TRIVIAL(debug)   <<
    "In makeDendrogram" << std::endl;

  for(std::map<std::string,
        std::map<std::string, std::vector<LAResult> > >::iterator k1_it =
        m_matrix.begin();
      k1_it != m_matrix.end();
      k1_it++)
    {
      leaf_set.insert(k1_it->first);
      for(std::map<std::string, std::vector<LAResult> >::iterator k2_it =
            (k1_it->second).begin();
          k2_it != (k1_it->second).end();
          k2_it++)
        {
          leaf_set.insert(k2_it->first);
        }

    }
  BOOST_LOG_TRIVIAL(debug)   <<
    "leaf_set size: " << leaf_set.size() << std::endl;

  std::vector<boost::shared_ptr<tree<TreeNode> > > old_tree_set;
  std::vector<boost::shared_ptr<tree<TreeNode> > > new_tree_set;

  for(std::set<std::string>::iterator leaf_it = leaf_set.begin();
      leaf_it != leaf_set.end();
      leaf_it++)
    {
      std::set<std::string> md5_set;
      md5_set.insert(*leaf_it);
      TreeNode root(-1,md5_set);
      boost::shared_ptr<tree<TreeNode> > tmp_tree(new tree<TreeNode>());
      tree<TreeNode>::iterator top;
      top = tmp_tree->begin();
      tmp_tree->insert(top,root);
      old_tree_set.push_back(tmp_tree);
    }

  BOOST_LOG_TRIVIAL(debug)   <<
    "old tree set size: " << old_tree_set.size() << std::endl;

  new_tree_set = old_tree_set;

  while(new_tree_set.size() != 1)
    {
      old_tree_set = new_tree_set;

      int cnt1 = 0;
      int merge_index_1;
      int merge_index_2;
      int max_val = -100.0;

      BOOST_LOG_TRIVIAL(debug)   <<
        "New tree set size " << new_tree_set.size() << std::endl;

      for(std::vector<boost::shared_ptr<tree<TreeNode> > >::iterator tree1_it =
            new_tree_set.begin();
          tree1_it != new_tree_set.end();
          tree1_it++)
        {
          BOOST_LOG_TRIVIAL(debug)   <<
            "Outer count is " << cnt1 << std::endl;

          std::set<std::string> &set1 =
            (**tree1_it).begin()->getMd5Set();
          int cnt2 = 0;
          for(std::vector<boost::shared_ptr<tree<TreeNode> > >::iterator
                tree2_it = new_tree_set.begin();
              tree2_it != new_tree_set.end();
              tree2_it++)
            {
              BOOST_LOG_TRIVIAL(debug)   <<
                "Inner count is " << cnt2 << std::endl;
              if(cnt2 >= cnt1)
                continue;
              std::set<std::string> &set2 =
                (**tree2_it).begin()->getMd5Set();
              BOOST_LOG_TRIVIAL(debug)   <<
                "Before  getMaxEditDistVal" << std::endl;

              int group_dist = getMaxEditDistVal(set1, set2);
              BOOST_LOG_TRIVIAL(debug)   <<
                "After getMaxEditDistVal" << std::endl;

              BOOST_LOG_TRIVIAL(debug)   <<
                "Group Distance: " << group_dist << std::endl;

              if(group_dist > max_val)
                {
                  max_val = group_dist;
                  merge_index_1 = cnt1;
                  merge_index_2 = cnt2;
                }

              cnt2++;
            }
          cnt1++;
        }
      new_tree_set = std::vector<boost::shared_ptr<tree<TreeNode> > >();

      for(int i = 0;i<old_tree_set.size();i++)
        {
          if(i == merge_index_1)
            {
              std::set<std::string> tmp_set;

              tmp_set.insert((*old_tree_set[i]).begin()->getMd5Set().begin(),
                             (*old_tree_set[i]).begin()->getMd5Set().end());
              tmp_set.insert((*old_tree_set[merge_index_2]).begin()->
                             getMd5Set().begin(),
                             (*old_tree_set[merge_index_2]).begin()->
                             getMd5Set().end());
              TreeNode new_root(max_val,tmp_set);
              boost::shared_ptr<tree<TreeNode> >
                new_root_tree(new tree<TreeNode>());
              tree<TreeNode>::iterator top;
              top = new_root_tree->begin();
              tree<TreeNode>::iterator new_root_it =
                new_root_tree->insert(top,new_root);
              tree<TreeNode>::iterator ots1 = old_tree_set[i]->begin();
              tree<TreeNode>::iterator ots2 =
                old_tree_set[merge_index_2]->begin();
              new_root_tree->append_child(new_root_it,ots1);
              new_root_tree->append_child(new_root_it,ots2);
              BOOST_LOG_TRIVIAL(debug)   <<
                "new_root_tree size1: " << new_root_tree->size() << std::endl;

              new_tree_set.push_back(new_root_tree);
            }
          else if(i == merge_index_2)
            {
            }
          else
            {
              new_tree_set.push_back(old_tree_set[i]);
            }
        }
    }
  setDendrogramTree(new_tree_set[0]);
  return new_tree_set[0];

}


int
Dendrogram::getMaxEditDistVal(const std::set<std::string> &set1,
                              const std::set<std::string> &set2)
{
  int max_score = -100;

  BOOST_LOG_TRIVIAL(debug)   <<
    "In getMaxEditDistVal" << std::endl;
  for(std::set<std::string>::iterator sit1 = set1.begin();sit1 != set1.end();
      sit1++)
    {
      for(std::set<std::string>::iterator sit2 = set2.begin();
          sit2 != set2.end();sit2++)
        {
          if(*sit1 != *sit2)
            {
              int e_dist;
              unsigned int key1 = strtoul((*sit1).c_str(),NULL,16);
              unsigned int key2 = strtoul((*sit2).c_str(),NULL,16);
              BOOST_LOG_TRIVIAL(debug)   <<
                "key1: " << key1 << " key2: " << key2 << std::endl;

              BOOST_LOG_TRIVIAL(debug)   <<
                "hex1: " << *sit1 << " hex2: " << *sit2 << std::endl;

              if(key1 < key2)
                {
                  if(m_matrix.find(*sit1) == m_matrix.end())
                    {
                      BOOST_LOG_TRIVIAL(error) <<
                        "First index " << *sit1 << "not found" <<
                        std::endl;

                      exit(-1);
                    }
                  else if(m_matrix[*sit1].find(*sit2) ==
                          m_matrix[*sit1].end())
                    {
                      BOOST_LOG_TRIVIAL(error) <<
                        "Second index " << *sit2 << "not found" <<
                        std::endl;
                      exit(-1);
                    }
                  e_dist = m_matrix[*sit1][*sit2][0].getMaxVal();
                }
              else
                {
                  if(m_matrix.find(*sit2) == m_matrix.end())
                    {
                      BOOST_LOG_TRIVIAL(error) <<
                        "Flip First index " << *sit2 << "not found" <<
                        std::endl;
                    }
                  else if(m_matrix[*sit2].find(*sit1) ==
                          m_matrix[*sit2].end())
                    {
                      BOOST_LOG_TRIVIAL(error) <<
                        "Flip Second index " << *sit1 << "not found" <<
                        std::endl;
                    }
                  e_dist = m_matrix[*sit2][*sit1][0].getMaxVal();
                }
              BOOST_LOG_TRIVIAL(debug)   <<
                "e_dist: " << e_dist << std::endl;

              if(e_dist > max_score)
                {
                  max_score = e_dist;
                }
            }
        }
    }
  return max_score;
}

std::vector<std::set<std::string> >
Dendrogram::findDisjointStringSets()
{
  double lpt;
  if(m_properties.has_key("Dendrogram.LevelPercentThresh"))
    {
      lpt =
        boost::python::extract<double>(m_properties
                                       ["Dendrogram.LevelPercentThresh"]);
     }

  std::vector<std::string> leaves = getDTreeLeaves();
  BOOST_LOG_TRIVIAL(debug)   << "Number of leaves: " <<
    leaves.size() << std::endl;

  // We now find all tree nodes where there is a jump in score beyond the
  // threshold

  std::vector<std::string> thresh_nodes;
  std::map<int,std::vector<tree<TreeNode>::iterator > >leaf_depth;
  std::vector<int> leaf_depths;

  // We sort leaves by depth
  for(tree<TreeNode>::iterator it = (*m_dendrogram_tree).begin();
      it != (*m_dendrogram_tree).end();it++)
    {
      int depth = (*m_dendrogram_tree).depth(it);
      leaf_depth[depth].push_back(it);
      leaf_depths.push_back(depth);
    }
  BOOST_LOG_TRIVIAL(debug)   << "Num leaf_depths " <<
    leaf_depths.size() << std::endl;

  std::sort(leaf_depths.begin(),leaf_depths.end());
  std::reverse(leaf_depths.begin(),leaf_depths.end());

  std::set<std::set<std::string> > node_above_visited;

  std::vector<std::vector<std::string> > string_sets;
  std::vector<std::set<std::string> > return_val;
  for(std::vector<int>::iterator it = leaf_depths.begin();
      it != leaf_depths.end();it++)
    {
      for(std::vector<tree<TreeNode>::iterator >::iterator tnit =
            leaf_depth[*it].begin();
          tnit != leaf_depth[*it].end();
          tnit++)
        {
          std::set<std::string> &md5_list = (**tnit).getMd5Set();
          tree<TreeNode>::iterator node_above_it;
          bool unified_flag =
            backup2Thresh(*tnit,*m_dendrogram_tree,lpt,node_above_it);
          if(node_above_visited.find((*node_above_it).getMd5Set()) !=
             node_above_visited.end())
            {
              continue;
            }
          else
            {
              node_above_visited.insert((*node_above_it).getMd5Set());
            }
          if(node_above_it == (*m_dendrogram_tree).begin())
            {
              std::set<std::string> &root_md5_list =
                (*node_above_it).getMd5Set();



              if(return_val.size() > 0)
                {
                  if(unified_flag)
                    {
                      return_val.push_back(root_md5_list);
                      return return_val;
                    }
                  else
                    {
                      tree<TreeNode>::sibling_iterator child_it =
                        (*m_dendrogram_tree).begin(node_above_it);
                      while(child_it != (*m_dendrogram_tree).end(node_above_it))
                        {
                          std::set<std::string> &string_set =
                            (*child_it).getMd5Set();
                          return_val.push_back(string_set);
                          child_it++;
                        }
                      return return_val;
                    }
                }
            }
          tree<TreeNode>::sibling_iterator child_it =
            (*m_dendrogram_tree).begin(node_above_it);
          while(child_it != (*m_dendrogram_tree).end(node_above_it))
            {
              std::set<std::string> &string_set =
                (*child_it).getMd5Set();
              return_val.push_back(string_set);
              child_it++;
            }

        }
    }
  return return_val;
}


std::vector<std::string>
Dendrogram::getDTreeLeaves()
{
  std::vector<std::string> leaves;

  BOOST_LOG_TRIVIAL(debug) << "Size of dendrogram tree: " <<
    (*m_dendrogram_tree).size() << std::endl;


  for(tree<TreeNode>::leaf_iterator lit = (*m_dendrogram_tree).begin_leaf();
      lit != (*m_dendrogram_tree).end_leaf();lit++)
    {
      leaves.insert(leaves.end(),(*lit).getMd5Set().begin(),
                    (*lit).getMd5Set().end());
    }
  return leaves;
}

bool
Dendrogram::backup2Thresh(tree<TreeNode>::iterator &leaf_it,tree<TreeNode> &tr,
                          double percent_thresh,
                          tree<TreeNode>::iterator &ex_node_it)
{
  if(leaf_it == tr.begin())
    {
      ex_node_it = leaf_it;
      return false;
    }

  tree<TreeNode>::iterator parent_it =
    tr.parent(leaf_it);

  if(parent_it == tr.begin())
    {
      ex_node_it = parent_it;
      return false;
    }

  tree<TreeNode>::iterator cur_node_it = parent_it;

  parent_it = tr.parent(cur_node_it);

  if(parent_it == tr.begin())
    {
      int cur_score = (*cur_node_it).getMaxScore();
      int par_score = (*parent_it).getMaxScore();

      double percent_diff = std::abs(cur_score - par_score)/double(cur_score);

      if(percent_diff >= percent_thresh)
        {
          ex_node_it = parent_it;
          return false;
        }
      else
        {
          ex_node_it = parent_it;
          return true;
        }
    }

  while(parent_it != tr.begin())
    {
      int cur_score = (*cur_node_it).getMaxScore();
      int par_score = (*parent_it).getMaxScore();

      double percent_diff = std::abs(cur_score - par_score)/double(cur_score);

      if(percent_diff >= percent_thresh)
        {
          ex_node_it = parent_it;
          return false;
        }
      cur_node_it = parent_it;
      parent_it = tr.parent(parent_it);
    }
  ex_node_it = tr.begin();
  return true;
}

std::vector<std::string>
Dendrogram::gatherSubsequences(std::set<std::string> &md5_list)
{
  BOOST_LOG_TRIVIAL(debug)   <<
    "md5_list size: " << md5_list.size() << std::endl;

  std::vector<std::string> md5_vec(md5_list.begin(),md5_list.end());
  std::sort(md5_vec.begin(),md5_vec.end());

  std::vector<std::string> subseq_list;

  for(std::map<std::string,
        std::map<std::string, std::vector<LAResult> > >::iterator  it1 =
        m_matrix.begin();
      it1 != m_matrix.end();it1++)
    {
      for( std::map<std::string, std::vector<LAResult> >::iterator it2 =
             (it1->second).begin();
           it2 != (it1->second).end();it2++)
        {
          BOOST_LOG_TRIVIAL(debug)   <<
            "m_matrix[" << it1->first << "][" << it2->first << "]"
                                     << std::endl;
        }
    }

  for(int i = 0;i < md5_vec.size();i++)
     {
       for(int j = i+1;j < md5_vec.size();j++)
        {
          BOOST_LOG_TRIVIAL(debug)   <<
            " Retrieving m_matrix[" << md5_vec[i] << "][" << md5_vec[j] << "]"
                                     << std::endl;
          LAResult entry = m_matrix[md5_vec[i]][md5_vec[j]][0];
          subseq_list.push_back(entry.getSubstringX());
          subseq_list.push_back(entry.getSubstringX());
        }
    }
  return subseq_list;
}
