#ifndef TRIE_ERROR_HH
#define TRIE_ERROR_HH

#include <exception>
#include <string>

/**
 * This is the parent class for all trie errors.
 */
class TrieError : public std::exception
{
public:
  /**
   * Default constructor.
   */
  TrieError();
  /**
   * This is a required virtual function by the abstract base class.
   * @return A string with the error message.
   */
  virtual const char *what() const throw()
  {
    return "Error: This is a generic Trie Error.\n";
  }
};

/**
 * This is an error being unable to open or read or write to the DiskTrie
 * file.
 */
class DiskTrieError : public TrieError
{
public:

  /**
   * An enum for various types of read, write and open errors.
   */
  typedef enum
    {
      Open, /**< Error in opening Trie DB file */
      Read, /**< Error in reading Trie DB file. */
      Write /**< Error in writing to Trie DB file. */
    } DiskTrieErrorType;

  /**
   * Default constructor.
   */
  DiskTrieError(std::string filename,DiskTrieErrorType error_type);
  /**
   * Destructor.
   */
  ~DiskTrieError() throw();
  /**
   * This is a required virtual function by the abstract base class.
   * @return A string with the error message.
   */
  virtual const char *what() const throw()
  {
    return m_error_string.c_str();
  }
private:
  std::string m_error_string;
};

/**
 * This is an error in attempting to cluster the per-attack packet tries.
 */
class ClusterError : public TrieError
{
public:

  /**
   * An enum for various types of read, write and open errors.
   */
  typedef enum
    {
      ExtractStrings,   /**< Error in extracting strings from Trie */
      IntersectStrings, /**< Error in intersecting Tries. */
      UnionStrings      /**< Error in union of Tries. */
    } ClusterErrorType;

  /**
   * Default constructor.
   */
  ClusterError(ClusterErrorType error_type);
  /**
   * Destructor.
   */
  ~ClusterError() throw();
  /**
   * This is a required virtual function by the abstract base class.
   * @return A string with the error message.
   */
  virtual const char *what() const throw()
  {
    return m_error_string.c_str();
  }
private:
  std::string m_error_string;
};
#endif
