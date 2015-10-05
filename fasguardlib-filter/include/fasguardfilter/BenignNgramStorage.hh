#ifndef BENIGN_NGRAM_STORAGE_HH
#define  BENIGN_NGRAM_STORAGE_HH
#include <map>
#include <string>
#include <inttypes.h>

/*!
 * \brief do-nothing function with C linkage
 *
 * This makes it possible to use GNU Autoconf's AC_CHECK_LIB() to find
 * libfasguardfilter.
 */
extern "C" void fasguardfilter();

/**
 * @brief This is an abstract base class that defines the interface for any
 *      storage implementation that holds ngrams of benign traffic.
 *
 * The implementations may vary. The first implementation will involve a
 * Bloom filter.
 */
class BenignNgramStorage
{
public:
  /**
   * Constructor. This accepts parameters that specify the benign traffic
   * independant of the form of storage. This constructor is used for the
   * initial construction of a BenignNgramStorage object, not restoring a
   * BenignNgramStorage object from persistant store.
   * @param ip_protocol_num This is the protocol field number that appears in
   *    the ip header.
   * @param port_num The tcp or udp port number of the captured traffic.
   * @param min_ngram_size The minimum number of bytes in a stored ngram.
   * @param max_ngram_size The maximum number of bytes in a stored ngram.
   */
  BenignNgramStorage(int ip_protocol_num, int port_num, int min_ngram_size,
                     int max_ngram_size);
  BenignNgramStorage()
  {}
  /**
   * This method is used for restoring a BenignNgramStorage
   * object from persistent store.
   * @param properties A map with a string to string mapping of keys to
   *    values for parameters.
   */
  void loadParams(const std::map<std::string,std::string> &properties);
  /**
   * Destructor.
   */
  virtual ~BenignNgramStorage();

  /**
   * Insert ngrams extracted from a string into the storage data structure.
   * @param data The content from the packet.
   * @param length The length of data.
   */
    virtual void insert(uint8_t const * data,
                        size_t length) = 0;

  /**
   * Check to see if a string is stored in the data structure. Typically, the
   * string is an ngram.
   * @param data The string to search for.
   * @param length The length of data.
   */
  virtual bool contains(uint8_t const * data,
                        size_t length) = 0;

  /**
   * Flush the data structure to a file.
   * @param filename Name of file used for persistence.
   */
  virtual bool flush(std::string filename) = 0;
  /**
   * Setter for number of bytes processed, set by PcapFileEngine.
   * @param num_bytes_processed Total number of payload bytes processed.
   */
  void setNumBytesProcessed(unsigned long long int num_bytes_processed);
  /**
   * Compares the parameters for two Bloom filters. Returns true if they are
   * compatible.
   * @param other Other Bloom filter's BenignNgramStorage element.
   * @return True if compatible, false if not.
   */
  bool Compare(const BenignNgramStorage &other);
protected:
  int m_ip_protocol_num;
  int m_port_num;
  int m_min_ngram_size;
  int m_max_ngram_size;
  uint_fast64_t m_insertions;
  uint_fast64_t m_unique_insertions;
  unsigned long long int m_bytes_processed;

};
#endif
