#include <boost/log/trivial.hpp>
#include <cmath>
#include <iostream>
#include <fstream>
#include <sstream>

#include <fasguardfilter.hpp>
#include <stdint.h>
#include <boost/regex.hpp>
#include "bloomfilter.hpp"
#include "MurmurHash3.h"

namespace fasguard
{

/**
    @brief Maximum number of hashes that any bloom filter can have.
*/
#define MAX_HASHES 512

  const static uint32_t HeaderLengthInBytes = 4096;
  static char Filler[HeaderLengthInBytes];

/**
    @brief Seeds for #MAX_HASHES different hash functions.

    For optimal performance, these should be random and unique.
*/
static uint_least32_t const hash_seeds[MAX_HASHES] = {
    0xc43d80bd, 0xd7fdaf8a, 0xa1c0a629, 0xcd03c982,
    0x62aaa4ef, 0x24ac65ee, 0x3213868e, 0x51b7449e,
    0x5bfa8f96, 0xf6bb5fae, 0x01ddf602, 0xe024fa98,
    0xa123ffb3, 0xb6f854cd, 0xcc79bf8d, 0x7ff681d4,
    0x72603637, 0xe82604a5, 0xe2124472, 0xd2775d38,
    0xd8a72c25, 0xc80e3619, 0x6e047553, 0x7c2ff0d4,
    0x81b260a9, 0x4894e3e0, 0x582f2c6b, 0xd275267d,
    0x313cd5a2, 0x6bf9e306, 0x3b5356c8, 0x10387e09,
    0x434d399e, 0x51a2e3a2, 0xe30c666c, 0x802b820b,
    0xcfe2ed88, 0x9ba3d03c, 0x7a26fe11, 0x2a10ca80,
    0x07be238e, 0x8383d461, 0xcf7477f8, 0x92e2e342,
    0x7afccf86, 0xb9f349f7, 0x28922e3c, 0x2a7587b1,
    0x236cbe14, 0x3c0e28e6, 0xaa370dd8, 0x20601d60,
    0x9565cf9a, 0x12455dfa, 0xefc7928a, 0x3b136279,
    0xc52d3db2, 0x110fe070, 0xd0a6530b, 0x8da1af86,
    0x1d2a0be0, 0x325a35fd, 0x711a812e, 0x668e20ab,
    0xf4c164a3, 0x89ce0078, 0x030eea8c, 0xecd8888e,
    0xabfd6907, 0x755043ab, 0x0789e2b4, 0x78fd3f2a,
    0x9ca63e66, 0x453ef58f, 0x9cd804ad, 0x07026237,
    0xb0fd476e, 0x5fa4f744, 0x84d71a8a, 0x9301b369,
    0x4b87dd39, 0x9a4933aa, 0xea74aaea, 0xa6f1851c,
    0x25536889, 0x92d1b6cc, 0x2b74f6a2, 0x20fa2e70,
    0x6f6b47ae, 0xffd4cdd0, 0x936ce9cb, 0x2e88d23a,
    0xa8798219, 0xf849e203, 0xc85c68e9, 0x5b66e4bc,
    0x67a9a888, 0xa398813a, 0x018c4065, 0xf6060229,
    0x5d469906, 0xce0c711e, 0x8183fb7f, 0x7354bb73,
    0x0e015ccf, 0x0f6e6345, 0x3f0c4ea9, 0xbd8ca2f2,
    0x03183e10, 0x67ce93ca, 0x29a37ce4, 0xf04317f7,
    0x6ab5e371, 0x2cdd9af9, 0x59a302fd, 0x7ab0551d,
    0xc90bab72, 0x0d3ddc29, 0xc33a8d1f, 0xe1571aba,
    0x7a3c86a9, 0x25badf9e, 0x3362e9b5, 0xb0b42dbf,
    0x4327da87, 0x2da56a3e, 0x14793925, 0xc84cd002,
    0x0179077b, 0x457abe9d, 0xe58b1155, 0x10f58219,
    0xb92126be, 0x449b0d8d, 0xe5f3cb28, 0x6a41e1e1,
    0x5e144cb9, 0x980800f5, 0x300484ed, 0x7fe4beab,
    0x9bac4fe5, 0x2c6b9243, 0x750b6af7, 0xda377e43,
    0x249e2431, 0xe1da513b, 0xfa012fad, 0xa641d9fe,
    0xab6993c1, 0xaf8c4033, 0xddd20ccb, 0xb4ac1cc9,
    0x04458831, 0x5e39703f, 0x16510a1d, 0x8d443441,
    0xdc636eb3, 0x0c4c3269, 0x2d1bc038, 0x6fcd504b,
    0x587559ae, 0x26bf34a5, 0x48975c19, 0xcfb377a7,
    0xaafe9bb5, 0xfc062aa5, 0xacbcc9a1, 0x0112c999,
    0x178beeed, 0x3849ce88, 0x28277412, 0x28dec7e8,
    0xd72a5657, 0x8807aa93, 0x7cd97d49, 0x38e464a7,
    0x1317e3ae, 0x4d88d988, 0x599b319f, 0xef85fadc,
    0xa83d0c9d, 0x3d197b55, 0x3c051316, 0xbce943f1,
    0x72fe247d, 0xa8428a26, 0xeacb3b51, 0x6c2d48a6,
    0x3c19ae25, 0x6f51fec7, 0x0b32ec54, 0x04f2cd70,
    0x5c0c5370, 0x14369ab6, 0x2bc82b6a, 0x8fb1cb7a,
    0x14a15cc0, 0x2ab75743, 0x3db1ecf7, 0xd3b44899,
    0xb5b4343e, 0xd1b898d4, 0x14df359d, 0xed2f1c7e,
    0x09118ca8, 0x64c9b199, 0x4397bffe, 0xd0b356fd,
    0xf7625e53, 0x46ca4426, 0x7441993c, 0xe2698108,
    0x3f8b774d, 0x28d5cd82, 0x5b6b7590, 0xfc4d639c,
    0xaa56d38a, 0x1b0fb3a9, 0x9b7247a8, 0x06c087e5,
    0xbf3f4387, 0x940c8818, 0x2ed50079, 0x4406574b,
    0x23e76902, 0xf4d9cb1e, 0xbc704918, 0xf3f3dff7,
    0xb4d3970c, 0x15d0e4d1, 0xf400b61f, 0x14b27033,
    0x675c8795, 0xb2616c53, 0xa2335267, 0xb956b855,
    0xf0721693, 0xa380630c, 0x60d40293, 0xb331145d,
    0x4916f240, 0x2be28c38, 0x90c011fd, 0xf927695e,
    0x8e7f58a9, 0xbb3d0625, 0x7f4c7c5f, 0xb3cbff89,
    0xc2720eb7, 0xb94524fe, 0x1e6d1344, 0x748cd53b,
    0xa2bcdb10, 0xab0d57e2, 0x1574a6c2, 0xe7c59596,
    0x9666f33f, 0x0f145c22, 0x755b0e80, 0x9ff8acff,
    0xcceaebf9, 0x8f139686, 0xe548d280, 0x2a9a7c3e,
    0x1b87a725, 0x05ed4b40, 0xa1da9db5, 0x30073999,
    0x7b8b438f, 0x99aaec1a, 0x89b29eea, 0xe19a7699,
    0xe0277bdd, 0x375368fe, 0xf9a41176, 0x67921b9b,
    0x0f67179e, 0x2f79cd76, 0x2cd55085, 0xc5966b4e,
    0x9b6a2a6d, 0x2117dcd9, 0xc1821c13, 0xd04509f1,
    0x6527b5a9, 0xd3e3df62, 0x735d372b, 0xe6c25b84,
    0xc04d5f80, 0x6c25b9fa, 0xddb17756, 0x9f07ac7c,
    0xd761a35c, 0x5bb5d328, 0x09c933e1, 0x079384f5,
    0x0d007a0e, 0x4f8ac9cd, 0x3462cb49, 0xe23d9db6,
    0x36da5846, 0x0ebe05b6, 0x531fc25f, 0x3e0c4b6a,
    0x0d2ba47d, 0xfa249fd5, 0x32fcadf5, 0xba90a52f,
    0x7b1a5188, 0x341e8b6c, 0xb3b629b9, 0x3389d618,
    0xdfafae14, 0xe8b46c6d, 0x7d0c8e4e, 0xf591c92b,
    0xa2836754, 0x5a5650e8, 0xfedca254, 0x0905041c,
    0x5d0ed76f, 0x936014a8, 0x4a65dede, 0xd2b1967e,
    0x5ecd0f45, 0x553ae734, 0xc64627e7, 0x6a7dacbb,
    0xbea5b678, 0xfe1dc7b5, 0x614a55e1, 0xc0b67e48,
    0xd9efc308, 0x4e739e72, 0x55f6af7f, 0xf36dd30e,
    0xba15d8d5, 0x09728396, 0x7bb9a349, 0x66061465,
    0xb8444771, 0xa1a7cdc4, 0x1aaa30c6, 0x672ee1ec,
    0x5ba9590c, 0xf761f997, 0x27dde0af, 0x3951c552,
    0x49e930d3, 0x8f673f8e, 0x64da6b23, 0x2b603bfa,
    0x2cea0fe2, 0x0e561615, 0xca6f090a, 0x34f9a5a1,
    0x68a92897, 0xf0aceaeb, 0x2826294e, 0x91118a53,
    0x4e712dbd, 0x00588325, 0x816d6df7, 0xed1bdc9c,
    0x07ca84b6, 0x5af316e0, 0xe72b05bd, 0xfa272baa,
    0x3e091d47, 0xa4123815, 0x7a72dbcd, 0x6cb5a13a,
    0xe6a0c4b3, 0x4d55f318, 0x9262aff4, 0x991b117b,
    0x8296dc82, 0x399412c1, 0x1701030e, 0x4bc4f24c,
    0x92901440, 0x639b16e8, 0x87a60f1d, 0xba42ffbb,
    0x7d92d28e, 0x60af85e4, 0xe4eca57e, 0xc59a9a23,
    0x7142bf72, 0xbf6d17a2, 0x75fb03c7, 0x83fe058b,
    0x916e5dc2, 0xe2198576, 0x6da7bb20, 0xb5224dfb,
    0x7f9d7769, 0x83f0a52f, 0xa5536c4e, 0x236dfec2,
    0xf52e2f8c, 0x25ae06e6, 0x1ef95a81, 0x3f7f1cba,
    0x239a3407, 0xf8bfb257, 0x030c27f4, 0x3fdb60fc,
    0x7c7a0da7, 0x6856a3b4, 0x5b96eee4, 0x9f7bd9f1,
    0x8c54cfa3, 0x78b382ed, 0x7b722a8e, 0x7e60c310,
    0x19fb1790, 0xe0d7180e, 0x46ba7a83, 0xd06996b4,
    0x549f0dcb, 0x1a36f9f9, 0x9dcc1dce, 0xd1be16a0,
    0x14aff0cb, 0x18978b6c, 0x5cfa5dd3, 0x8f398826,
    0x97f27eea, 0xbfea4034, 0x94c7c342, 0xeefeb95a,
    0x6e9e2988, 0x34f8445e, 0x5705963e, 0x9491c90e,
    0xd2b7c1ec, 0x118a3b6e, 0xae4ec065, 0x2985730a,
    0x7209e913, 0x73220575, 0x917393a3, 0x043310dd,
    0xbd6973a3, 0x7649e2ef, 0x10d25e18, 0x14a1c1e1,
    0x0d3a78dd, 0x20002765, 0xbd390227, 0x03766496,
    0x646fc64a, 0xdddd94c2, 0xfa426cd4, 0xc4fb95d0,
    0xb450e67d, 0xd62b8a5e, 0xe4a4dbe3, 0x9346aeb5,
    0x9aee2ad6, 0x0fe781ae, 0xc17680d4, 0x2e298a36,
    0xc3094233, 0x3354e2d0, 0x286cff90, 0x26f624a6,
    0x72efeff0, 0x036d6fc8, 0x5de8acc6, 0x5d4f36c9,
    0x3fb0589c, 0x552451da, 0x8ecd9bee, 0xdcfb4823,
    0xfe925b8d, 0x317627e3, 0x977a2d36, 0x1325c25f,
    0xb6eeb1a3, 0xdcb0632e, 0xaf6f5408, 0xcd896b06,
    0x1537bb8f, 0x70b30d2f, 0xe93313b8, 0xb020bd3f,
    0x8a82550a, 0x2c3be924, 0x4e8f99cd, 0x4a10d46d,
    0x81975ce3, 0xa3cd36da, 0xfa6cf6b2, 0x7167da7e,
    0x948c22ba, 0x18a69fea, 0xce5dd4e4, 0x848c5898,
    0xe4760876, 0x0583c930, 0x894688c9, 0x07978faf,
    0xb82f11d7, 0xc1748f94, 0xda12646e, 0x54b37e21,
    0x4943a229, 0x79516926, 0x31d072d4, 0xf52d59c9,
};

  /**
   * Array of bit masks for optimizing computation with the Bloom filter
   */
  static const unsigned char BIT_MASK[] = { 0x01,   //00000001
                                            0x02,   //00000010
                                            0x04,   //00000100
                                            0x08,   //00001000
                                            0x10,   //00010000
                                            0x20,   //00100000
                                            0x40,   //01000000
                                            0x80 }; //10000000

/**
    @brief Compute a hash.

    @todo Implement this. There are a number of pitfalls to avoid:
        - Boost and the STL provide hash functions, and boost provides
          hash_combine to hash multiple items in order. Those are
          probably all useless here for a two related reasons:
          - They use size_t arithmetic instead of fixed-width
            arithmetic. A hash computed with one size of size_t
            will probably not be equal to the hash of the same data
            computed with a different sized size_t.
          - They don't appear to guarrantee the same hash results
            across time, platforms, implementations, or much of
            anything else that can change between when one program
            computes a hash and another program computes a hash of
            the same data.
        - In general, the modulo operator does not map a uniform
          distribution to another uniform distribution. E.g., if you
          compute <tt>x</tt> uniformly distributed in
          [0, <tt>UINT64_MAX</tt>], then <tt>x % bins</tt> is not
          guranteed to be uniformly distributed. If <tt>bins</tt>
          is a power of two, this problem is avoided.
        - Computing hashes with blind multiplication is a bad idea.
          Once you've multiplied 64 even numbers, the
          least-significant 64 bits of the result are all zero.

    @param[in] hash_number Which hash to compute. Must be less than
        #MAX_HASHES.
    @param[in] bins Number of bins in the filter.
    @param[in] data Data to hash.
    @param[in] length Length of @p data.
    @return An integer uniformly distributed in the range
        [0, <tt>bins</tt>).
*/
static bloom_filter_parameters::index_type compute_hash(
    size_t hash_number,
    bloom_filter_parameters::index_type bins,
    uint8_t const * data,
    size_t length)
{
    return 0; // XXX: this is wrong, of course
}


// Calculations are based on
// http://en.wikipedia.org/wiki/Bloom_filter#Probability_of_false_positives
// http://en.wikipedia.org/w/index.php?title=Bloom_filter&oldid=629694098
// If you make changes to this function, remember to avoid floating-
// point rounding issues.
bloom_filter_parameters::bloom_filter_parameters(
                                                 size_t items,
                                                 double
                                                 probability_false_positive,
                                                 int ip_protocol_num,
                                                 int port_num,
                                                 int min_ngram_size,
                                                 int max_ngram_size
                                                 )
:
  serializable_filter_parameters(),m_ip_protocol_num(ip_protocol_num),
  m_port_num(port_num),m_min_ngram_size(min_ngram_size),
  m_max_ngram_size(max_ngram_size)
{
  BOOST_LOG_TRIVIAL(debug) << "Expected number of insertions: " <<
    items << std::endl;
  BOOST_LOG_TRIVIAL(debug) << "Desired probability of false alarm: " <<
    probability_false_positive << std::endl;

    // Calculate optimal number of bits and round to the nearest
    // integer.
    bitlength = llround(
        (-1.0 * (double)items * log(probability_false_positive)) /
        (M_LN2 * M_LN2));

    // Always round up to a power of 2

    unsigned long int bitlength_guess = 1;
    BOOST_LOG_TRIVIAL(debug) << "Start bitlength: " <<
      bitlength << std::endl;
    for(int i = 0;i < (sizeof(unsigned long int)*8);i++)
      {
        bitlength_guess = 1L << i;

        if(bitlength_guess > bitlength)
          {
            bitlength = bitlength_guess;
            break;
          }
      }

    if (bitlength % 8 != 0)
    {
        // Round bitlength up to the nearest byte.
        bitlength += 8 - (bitlength % 8);
    }
    else if (bitlength < 1)
    {
        // A zero-size bloom filter is useless.
        bitlength = 8;
    }
    BOOST_LOG_TRIVIAL(debug) << "Bitlength: " <<
      bitlength << std::endl;

    // Calculate optimal number of hashes and round to the nearest
    // integer.
    m_num_hashes = llround(M_LN2 * (double)bitlength / (double)items);

    if (m_num_hashes < 1)
    {
        // A bloom filter won't work with zero hashes.
        m_num_hashes = 1;
    }
    else if (m_num_hashes > MAX_HASHES)
    {
        // Don't try to use more hashes than we can.
        m_num_hashes = MAX_HASHES;
    }
    BOOST_LOG_TRIVIAL(debug) << "Number of hashes: " <<
                             m_num_hashes << std::endl;

}

  bloom_filter_parameters::bloom_filter_parameters(const std::map<std::string,
                                                   std::string>
                                                   &bf_properties)
  {
    std::map<std::string,std::string>::const_iterator cit =
      bf_properties.begin();

    while(cit != bf_properties.end())
      {
        if((cit->first).compare(std::string("IP_PROTOCOL_NUMBER")) == 0)
          {
            std::istringstream(cit->second) >> m_ip_protocol_num;
          }
        else if((cit->first).compare(std::string("TCP_IP_PORT_NUM")) == 0)
          {
            std::istringstream(cit->second) >> m_port_num;
          }
        else if((cit->first).compare(std::string("BITLENGTH")) == 0)
          {
            std::istringstream(cit->second) >> bitlength;
          }
        else if((cit->first).compare(std::string("NUM_HASHES")) == 0)
          {
            std::istringstream(cit->second) >> m_num_hashes;
          }
        else if((cit->first).compare(std::string("MIN_NGRAM_SIZE")) == 0)
          {
            std::istringstream(cit->second) >> m_min_ngram_size;
          }
        else if((cit->first).compare(std::string("MAX_NGRAM_SIZE")) == 0)
          {
            std::istringstream(cit->second) >> m_max_ngram_size;
          }
        else
          {
            BOOST_LOG_TRIVIAL(error) << "Unknown property: " <<
              cit->first << std::endl;
          }
        cit++;
      }
  }

bloom_filter_parameters::~bloom_filter_parameters()
{
}

// TODO: Implement this or remove it from here and fasguardbloom.hpp.
// The formulas on the wikipedia page[0] are both of the form (1-X)^Y.
// If X is small and Y is large, the naive computation of that value
// is very prone to rounding issues and will be very very wrong.
// There's probably some trick to implement this correctly, but I
// don't know it off the top of my head. If we don't need this
// function, it's probably easiest to just remove it instead of
// trying to implement it.
//  [0] http://en.wikipedia.org/wiki/Bloom_filter#Probability_of_false_positives
double bloom_filter_parameters::probability_false_positive(
    size_t items)
    const
{
    return NAN; // XXX: this is wrong, of course
}

  bool bloom_filter_parameters::serialize(std::string &serialized_header)
  {
    std::ostringstream out;

    out << "IP_PROTOCOL_NUMBER = " << m_ip_protocol_num << std::endl;
    out << "TCP_IP_PORT_NUM = " << m_port_num << std::endl;
    out << "BITLENGTH = " << bitlength << std::endl;
    out << "NUM_HASHES = " << m_num_hashes << std::endl;
    out << "MIN_NGRAM_SIZE = " << m_min_ngram_size << std::endl;
    out << "MAX_NGRAM_SIZE = " << m_max_ngram_size << std::endl;
    serialized_header = out.str();
    return true;
  }


bloom_filter_statistics::bloom_filter_statistics()
:
    serializable_filter_statistics()
{
}

  bool bloom_filter_statistics::serialize(
                                          void * buffer,
                                          size_t & offset,
                                          size_t length) const
  {
    std::cerr << "bloom_filter_statistics::serialize not implemented" <<
      std::endl;
    exit(1);
  }

bool bloom_filter_statistics::unserialize(
                                          void const * buffer,
                                          size_t & offset,
                                          size_t length)
  {
    std::cerr << "bloom_filter_statistics::unserialize not implemented" <<
      std::endl;
    exit(1);
  }


bloom_filter::bloom_filter(
    bloom_filter_parameters * parameters_,
    bloom_filter_statistics * statistics_)
:
  file_backed_filter(parameters_, statistics_),
  mBloomFilter((parameters_->getBitLength()>>3),0)
{
  BOOST_LOG_TRIVIAL(debug) << "Bitlength in bloom_filter: " <<
    parameters_->getBitLength() << std::endl;
}

  bloom_filter::bloom_filter(std::string filename)
  {
    std::ifstream bf_stream(filename.c_str());

    if(!bf_stream)
      {
        BOOST_LOG_TRIVIAL(error) << "Unable to open: " <<
          filename << std::endl;
        exit(-1);

      }
    bf_stream.read(Filler,HeaderLengthInBytes);

    std::string bf_prop_string(Filler);

    // Now, extract the bloom filter file header information

    std::map<std::string,std::string> bf_properties;

    boost::regex exp("(\\w+)\\s*=\\s*(\\w+)");
    boost::match_results<std::string::const_iterator> what;
    std::string::const_iterator start = bf_prop_string.begin();

    BOOST_LOG_TRIVIAL(debug) << "List properties: "
                             << std::endl;
    while(boost::regex_search(start,bf_prop_string.cend(),what,exp))
      {
        bf_properties[what[1]] = what[2];
        BOOST_LOG_TRIVIAL(debug) << what[1] << " = " << what[2]
                                 << std::endl;
        start = what[0].second;
      }
    bloom_filter_parameters *bloom_parameters =
      new bloom_filter_parameters(bf_properties);
    parameters = bloom_parameters;
    statistics =
      new bloom_filter_statistics();
    std::streampos bloom_size = bloom_parameters->getBitLength()>>3;
    mBloomFilter.resize(bloom_size);
    bf_stream.read((char *)&mBloomFilter[0], bloom_size);
    BOOST_LOG_TRIVIAL(debug) << "Finished constructing bloom_filter"
                             << std::endl;

  }

bloom_filter::~bloom_filter()
{
}

  std::string bloom_filter_parameters::to_string() const
  {
    std::cerr << "bloom_filter_parameters::to_string not implemented" <<
      std::endl;
    exit(1);
    return std::string("");
  }

  bool bloom_filter_parameters::serialize(
                                          void * buffer,
                                          size_t & offset,
                                          size_t length)
    const
  {
       std::cerr << "bloom_filter_parameters::serialize not implemented" <<
         std::endl;
       exit(1);
       return false;
  }

  bool bloom_filter_parameters::unserialize(
                   void const * buffer,
                   size_t & offset,
                   size_t length)
  {
        std::cerr << "bloom_filter_parameters::unserialize not implemented" <<
         std::endl;
       exit(1);
       return false;
 }


  std::string bloom_filter::to_string() const
  {
    std::cerr << "bloom_filter::to_string not implemented" <<
      std::endl;
    exit(1);
    return std::string("");
  }

  void bloom_filter::insert(
                            uint8_t const * data,
                            size_t length)
  {
  //cout << "'";
  //cout.write((const char *)str,lgth);
  //cout << "'";

  //cout << endl;
  // number of Ngram hash functions in our list
    //bloom_filter *this_bloom = const_cast<bloom_filter *>(this);
    bloom_filter_parameters *bfp =
      dynamic_cast<bloom_filter_parameters *>(getFilterParameters());
    const size_t num_hash_func =
      const_cast<bloom_filter_parameters *>(bfp)
      ->getNumHashes();

  // Process the Ngram with each hash function in our list.
  for(size_t i = 0 ; i < num_hash_func ; i++)
  {
    // compute the bit index into the Bloom filter where this Ngram will
    // be marked
    // unsigned long int bit_index = mHashFuncList[i](str,lgth) % (mFilterSizeBytes * CHAR_SIZE_BITS);
    uint64_t filterSizeInBits =
      const_cast<bloom_filter_parameters *>(bfp)
      ->getBitLength();

    uint64_t hash_pair[2];
    MurmurHash3_x86_128(data,length,hash_seeds[i],hash_pair);
    uint64_t bit_index
      = hash_pair[1] %
      filterSizeInBits;

    // mark the appropriate bit in the Bloom filter to indicate that this
    // Ngram has been seen
    mBloomFilter[bit_index / CHAR_SIZE_BITS] |= BIT_MASK[bit_index % CHAR_SIZE_BITS];

    //cout << "Hash: " << i << ",bit_index = " << bit_index << endl;
  }

  }
  bool bloom_filter::insert_all(
                                filter const & other)
  {
    std::cerr << "bloom_filter::insert_all not implemented" <<
      std::endl;
    exit(1);
    return false;
  }

  bool bloom_filter::contains(
                          uint8_t const * data,
                          size_t length)
  {
    // number of Ngram hash functions in our list
    //bloom_filter *this_bloom = const_cast<bloom_filter *>(this);
    bloom_filter_parameters *bfp =
      dynamic_cast<bloom_filter_parameters *>(getFilterParameters());
    const size_t num_hash_func =
      const_cast<bloom_filter_parameters *>(bfp)
      ->getNumHashes();

    // std::cout << "In contains, number hashes is " << num_hash_func <<
    //   std::endl;
    uint64_t filterSizeInBits =
      const_cast<bloom_filter_parameters *>(bfp)
      ->getBitLength();
    // std::cout << "filterSizeInBits = " << filterSizeInBits << std::endl;

     //mHashFuncList.size();

  // Process the Ngram with each hash function and see if it exists in
  // the Bloom filter. Notice that the Ngram is only declared to be
  // contained by the Bloom filter if *all* the hash functions report
  // its existence.
  for(size_t i = 0 ; i < num_hash_func ; i++)
  {
    // bit index into the Bloom filter where this Ngram would have been marked
    // by the i'th hash function
    uint64_t hash_pair[2];
    MurmurHash3_x86_128(data,length,hash_seeds[i],hash_pair);
    uint64_t bit_index
      = hash_pair[1] %
      filterSizeInBits;

    // the bit index relative to the start of that byte
    uint64_t bit = bit_index % CHAR_SIZE_BITS;

    // if the given bit index in the Bloom filter hasn't been marked, we
    // definitely have never seen this Ngram before
    if((mBloomFilter[bit_index / CHAR_SIZE_BITS] & BIT_MASK[bit]) != BIT_MASK[bit])
    {
      return(false);
    }
  }

  // It appears that the Ngram has been seen before
  // NOTE: This answer is not 100% reliable. See the class comments for details
  // on false drop probability

  // BOOST_LOG_TRIVIAL(debug) <<
  //   "BloomFilter Matched String!!! " << std::endl;

  return(true);

  }


  bool
  bloom_filter::flush()
  {
    std::string serialized_header;

    bloom_filter *this_bloom = const_cast<bloom_filter *>(this);
    bloom_filter_parameters *bfp =
      dynamic_cast<bloom_filter_parameters *>(this_bloom->getFilterParameters());
    bfp->serialize(serialized_header);

    const char *persist_filename = m_persistant_file.c_str();
    std::ofstream bfStream(persist_filename);

    if(!bfStream)
      {
        BOOST_LOG_TRIVIAL(error) <<
          "Unable to open: " << m_persistant_file << std::endl;
        return false;
      }
    const char *raw_bytes =
      reinterpret_cast<const char *>(serialized_header.c_str());
    unsigned int raw_size = serialized_header.size();

    bfStream.write(raw_bytes,raw_size);
    bfStream.write(Filler,HeaderLengthInBytes-raw_size);

    std::vector<uint8_t>::iterator it = mBloomFilter.begin();

    //  bfStream.write(it,mBloomFilter.size());

    while(it != mBloomFilter.end())
      {
        bfStream.put(*(it++));
      }

    bfStream.close();
  }

}