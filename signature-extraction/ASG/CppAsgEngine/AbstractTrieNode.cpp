#include <iostream>
#include <stdint.h>
#include "AbstractTrieNode.h"
#include "TrieNodeFactorySpecialization.h"

using namespace std;

AbstractTrieNode::AbstractTrieNode(AbstractTrieNodeFactory &atnf)
  : m_atnf(atnf)
{}

boost::shared_ptr<AbstractTrieNode>
AbstractTrieNode::insertChar(unsigned int c,bool end_string,
                             unsigned int inc_num_insertions)
{
  // Since we are inserting a character, we are no longer a leaf

  setLeafFlag(false);


  if(getNumChildren() == 0)
    {
      // There are no children and we need to insert a new node

      uint64_t new_index;
      boost::shared_ptr<AbstractTrieNode> new_node =
        m_atnf.newNode(new_index);
      if(!new_node)
        return new_node;
      setChildIndex(c,new_index);
      new_node->setMyChar(c);
      setNumChildren(1);
      new_node->setEndStringFlag(end_string);
      new_node->setLeafFlag(true);
      new_node->setCleanupFlag(false);
      // May need more setting of parent data

      return new_node;
    }
  else
    {
      // We have existing links.  We check to see if there is an existing
      // link for the requested character

      bool err_flag;

      uint64_t child_index = getChildIndex(c,err_flag);

      if(err_flag)
        {
          BOOST_LOG_TRIVIAL(error)
            << "Bad child index: " << endl;
          return boost::shared_ptr<AbstractTrieNode>(); // Null boost::shared_ptr
        }

      if(child_index == 0)
        {
          // No child for this character.  Create new link.
          uint64_t new_index;
          boost::shared_ptr<AbstractTrieNode> new_node =
            m_atnf.newNode(new_index);
          setChildIndex(c,new_index);
          new_node->setMyChar(c);
          setNumChildren(getNumChildren()+1);
          new_node->setEndStringFlag(end_string);
          return new_node;
        }
      else
        {
          // Get child node

          boost::shared_ptr<AbstractTrieNode> child_node =
            m_atnf.retrieveNode(child_index);

          // Set end string flag if necessary

          if(!child_node->getEndStringFlag() && end_string)
            child_node->setEndStringFlag(end_string);
          return child_node;
        }
    }
}

bool
AbstractTrieNode::countNodes(unsigned int &count) const
{
  // Count myself
  count++;

  for(register unsigned int i=0;i<getAlphabetSize();i++)
    {
      bool err_flag;
      uint64_t next_index = getChildIndex(i,err_flag);
      if(err_flag)
        return false;
      if(next_index != 0)
        {
          boost::shared_ptr<AbstractTrieNode> next_node =
            m_atnf.retrieveNode(next_index);
          if(!next_node->countNodes(count))
            return false;
        }
    }
  return true;
}

bool AbstractTrieNode::intersectStrings(const AbstractTrieNode &other,
                                        AbstractTrieNode &result)
{
  if(getLeafFlag())
    return true;

  for(unsigned int char_val=0;char_val<getAlphabetSize();char_val++)
    {
      bool err_flag = false;
      uint64_t my_child_index = getChildIndex(char_val,err_flag);
      if(err_flag)
        {
          BOOST_LOG_TRIVIAL(error)
            << "ERROR.  Failure for char_val: "
            << char_val
            << endl;
          return false;
        }
      uint64_t other_child_index = other.getChildIndex(char_val,err_flag);
      if(err_flag)
        {
          BOOST_LOG_TRIVIAL(error)
            << "ERROR.  Failure for char_val: "
            << char_val
            << endl;
          return false;
        }

      if(my_child_index != 0 && other_child_index != 0)
        {
          // Retrieve child nodes

          boost::shared_ptr<AbstractTrieNode> my_child =
            m_atnf.retrieveNode(my_child_index);

          if(!my_child)
            {
              BOOST_LOG_TRIVIAL(error)
                << "Could not retrieve node for index: "
                << my_child_index << endl;
              return false;
            }

          boost::shared_ptr<AbstractTrieNode> other_child =
            other.m_atnf.retrieveNode(other_child_index);

          if(!other_child)
            {
              BOOST_LOG_TRIVIAL(error)
                << "Could not retrieve node for index: "
                << other_child_index << endl;
              return false;
            }

          // Create new node

          // Is this the end of string for both?
          bool end_string = false;
          bool leaf_flag = false;

          if(my_child->getEndStringFlag() && other_child->getEndStringFlag())
            end_string = true;

          // Is either a leaf node?

          if(my_child->getLeafFlag() || other_child->getLeafFlag())
            leaf_flag = true;

          boost::shared_ptr<AbstractTrieNode> new_node =
            result.insertChar(char_val,end_string);

          if(!new_node)
            {
              BOOST_LOG_TRIVIAL(error)
                << "Error in insertChar"
                << endl;
              return false;
            }

          // Fill in some more fields
          new_node->setLeafFlag(leaf_flag);

          // Recurse

          if(!my_child->intersectStrings(*other_child,*new_node))
            {
              BOOST_LOG_TRIVIAL(error)
                << "Error in recursion"
                << endl;
              return false;
            }

        }
    }
  return true;
}

bool AbstractTrieNode::unionStrings(boost::shared_ptr<AbstractTrieNode> cur,
                                    boost::shared_ptr<AbstractTrieNode> other,
                                    boost::shared_ptr<AbstractTrieNode> result)
{
  if((!cur) && (!other))
    return true;

  unsigned int alpha_size = (!cur)?other->getAlphabetSize():
    cur->getAlphabetSize();

  for(unsigned int char_val=0;char_val<alpha_size;char_val++)
    {
      bool err_flag = false;
      uint64_t cur_child_index = 0;

      if(cur)
        {
          cur_child_index = cur->getChildIndex(char_val,err_flag);
          if(err_flag)
            {
              BOOST_LOG_TRIVIAL(error)
                << "ERROR.  Failure for char_val: "
                << char_val
                << endl;
              return false;
            }
        }
      uint64_t other_child_index = 0;

      if(other)
        {
          other_child_index = other->getChildIndex(char_val,err_flag);
          if(err_flag)
            {
              BOOST_LOG_TRIVIAL(error)
                << "ERROR.  Failure for char_val: "
                << char_val
                << endl;
              return false;
            }
        }

      boost::shared_ptr<AbstractTrieNode> cur_child;
      boost::shared_ptr<AbstractTrieNode> other_child;

      // Is this the end of string for either?
      bool end_string = false;
      bool leaf_flag = false;

      if(cur_child_index == 0 && other_child_index == 0)
        continue;

      if(cur_child_index != 0)
        {

          // Retrieve child nodes

          cur_child =
            cur->m_atnf.retrieveNode(cur_child_index);

          if(!cur_child)
            {
              BOOST_LOG_TRIVIAL(error)
                << "Could not retrieve node for index: "
                << cur_child_index << endl;
              return false;
            }
          if(cur_child->getEndStringFlag())
            end_string = true;
        }

      if(other_child_index != 0)
        {
          other_child =
            other->m_atnf.retrieveNode(other_child_index);

          if(!other_child)
            {
              BOOST_LOG_TRIVIAL(error)
                << "Could not retrieve node for index: "
                << other_child_index << endl;
              return false;
            }
          if(other_child->getEndStringFlag())
            end_string = true;
        }

      if(cur_child && cur_child->getLeafFlag() &&
         other_child && other_child->getLeafFlag())
        leaf_flag = true;

      if(((!cur_child) && other_child->getLeafFlag())
         ||
         ((!other_child) && (!cur_child)))
        leaf_flag = true;

      boost::shared_ptr<AbstractTrieNode> new_node =
        result->insertChar(char_val,end_string);

      if(!new_node)
        {
          BOOST_LOG_TRIVIAL(error)
            << "Error in insertChar"
            << endl;
          return false;
        }

      // Fill in some more fields
      new_node->setLeafFlag(leaf_flag);

      // Recurse

      if(!cur_child->unionStrings(cur_child,other_child,new_node))
        {
          BOOST_LOG_TRIVIAL(error)
            << "Error in recursion"
            << endl;
          return false;
        }

    }

  return true;
}

bool
AbstractTrieNode::cleanup()
{
  for(register unsigned int i=0;i<getAlphabetSize();i++)
    {
      bool err_flag;

      uint64_t child_index = getChildIndex(i,err_flag);
      if(err_flag)
        return false;
      if(child_index == 0)
        continue;

      boost::shared_ptr<AbstractTrieNode> child = m_atnf.retrieveNode(child_index);

      if(child->getCleanupFlag())
        {
          // Delete all descendants

          // Set this nodes pointer to the deleted node to zero
          setChildIndex(i,0);
          m_atnf.deleteNode(child_index);
        }
      else
        {
          // check child for cleanup

          if(!child->cleanup())
            return false;
        }

    }

  return true;
}

bool
AbstractTrieNode::getAllStrings(std::vector<std::string> &string_list,
                                std::string cur_string)
{
  if(getEndStringFlag())
    {
      string_list.push_back(cur_string);
    }

  for(register unsigned int i=0;i<getAlphabetSize();i++)
    {
      bool err_flag;
      uint64_t child_index = getChildIndex(i,err_flag);
      if(err_flag)
        return false;
      if(child_index == 0)
        continue;

      boost::shared_ptr<AbstractTrieNode> child = m_atnf.retrieveNode(child_index);
      string cs(1,i);
      if(!child->getAllStrings(string_list,cur_string+cs))
        return false;
    }
  return true;
}

bool
AbstractTrieNode::trimBranchesAfterEndString()
{
  stack<boost::shared_ptr<AbstractTrieNode> > node_stack;
  return branchTrimmer(node_stack);
}

bool
AbstractTrieNode::branchTrimmer(std::stack<boost::shared_ptr<AbstractTrieNode> >
                                node_stack)
{
  if(getEndStringFlag())
    {
      // empty stack

      while(!node_stack.empty())
        {
          node_stack.pop();
        }
    }
  if(getLeafFlag())
    {
      while(!node_stack.empty())
        {
          node_stack.top()->setCleanupFlag(true);
          node_stack.pop();
        }
    }
  for(register unsigned int i=0;i<getAlphabetSize();i++)
    {
      bool err_flag;
      uint64_t child_index = getChildIndex(i,err_flag);
      if(err_flag)
        return false;
      if(child_index == 0)
        continue;

      boost::shared_ptr<AbstractTrieNode> child = m_atnf.retrieveNode(child_index);
      stack<boost::shared_ptr<AbstractTrieNode> > node_stack_copy(node_stack);
      node_stack_copy.push(child);
      if(!child->branchTrimmer(node_stack_copy))
        return false;
    }
  return true;
}


bool
AbstractTrieNode::eraseEndString(const AbstractTrieNode &other_node)
{
  if(other_node.getEndStringFlag() && getEndStringFlag())
    {
      setEndStringFlag(false);
    }

  for(register unsigned int i=0;i<getAlphabetSize();i++)
    {
      bool err_flag;
      uint64_t my_child_index = getChildIndex(i,err_flag);
      if(err_flag)
        return false;
      if(my_child_index == 0)
        continue;
      uint64_t other_child_index = other_node.getChildIndex(i,err_flag);
      if(err_flag)
        return false;
      if(other_child_index == 0)
        continue;

      boost::shared_ptr<AbstractTrieNode> my_child = m_atnf.retrieveNode(my_child_index);
      boost::shared_ptr<AbstractTrieNode> other_child = other_node.m_atnf.retrieveNode(other_child_index);
      my_child->eraseEndString(*other_child);
    }
  return true;
}

bool AbstractTrieNode::keepLastEndString(AbstractTrieNode *last_end_string)
{
  if(getEndStringFlag())
    {
      if(last_end_string == NULL)
        {
          last_end_string = this;
        }
      else
        {
          last_end_string->setEndStringFlag(false);
          last_end_string = this;
        }
    }

  for(register unsigned int i=0;i<getAlphabetSize();i++)
    {
      bool err_flag;
      uint64_t my_child_index = getChildIndex(i,err_flag);
      if(err_flag)
        return false;
      if(my_child_index == 0)
        continue;

      boost::shared_ptr<AbstractTrieNode> my_child = m_atnf.retrieveNode(my_child_index);
      my_child->keepLastEndString(last_end_string);
    }
  return true;
}

boost::shared_ptr<AbstractTrieNode>
AbstractTrieNode::matchChar(unsigned int c,bool &end_string,bool &err_flag) const
{
  uint64_t my_child_index = getChildIndex(c,err_flag);
  if(err_flag)
    {
      BOOST_LOG_TRIVIAL(error)
        << "Error in getChildIndex" << endl;
      return boost::shared_ptr<AbstractTrieNode>();
    }

  if(my_child_index == 0)
    {
      err_flag = false;
      return boost::shared_ptr<AbstractTrieNode>();
    }
  boost::shared_ptr<AbstractTrieNode> my_child = m_atnf.retrieveNode(my_child_index);
  end_string = my_child->getEndStringFlag();
  return my_child;
}
