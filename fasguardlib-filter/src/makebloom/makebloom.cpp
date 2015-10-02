#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/program_options.hpp>
#include <boost/shared_ptr.hpp>
#include <iostream>
#include <algorithm>
#include <iterator>
#include <pcap.h>
#include <fasguardfilter/BloomFilterUnthreaded.hh>
#include <fasguardfilter/BloomFilterThreaded.hh>
#include "PcapFileEngine.hpp"
//#include "MurmurHash3.h"

namespace logging = boost::log;
namespace po = boost::program_options;

using namespace std;

// A helper function to simplify the main part.
template<class T>
boost::log::formatting_ostream& operator<<(boost::log::formatting_ostream& os,
                                           const vector<T>& v)
{
  typedef typename vector<T>::const_iterator c_it_type;
  c_it_type ci = v.begin();
  while(ci != v.end())
    {
      os << *ci << " ";
      ci++;
    }
  return os;
}

/**
 * This program creates a bloom filter from a pcap file.
 */
int
main(int argc, char *argv[])
{
  double pfa;
  unsigned long int num_insertions;
  int ip_proto;
  int port_num;
  int min_depth;
  int max_depth;
  int thread_num;
  bool merge_flag;
  bool thread_flag;
  std::string out_file;

  po::variables_map vm;

  try
    {
      po::options_description desc("");
      desc.add_options()
        ("help,h", "produce help message")
        ("merge,m", po::bool_switch(&merge_flag)->default_value(false),
         "Mode for merging two Bloom filters into one")
        ("thread,t", po::bool_switch(&thread_flag)->default_value(false),
         "Run the multithreaded version")
        ("prob-fa", po::value<double>(&pfa)->default_value(0.00001),
         "desired probability of false alarm")
        ("num-insertions,n",
         po::value<unsigned long int>(&num_insertions)->default_value(10),
         "Maximum number of insertion strings")
        ("ip-proto",
         po::value<int>(&ip_proto)->default_value(6),
         "IP protocol number")
        ("port-num",
         po::value<int>(&port_num)->default_value(80),
         "TCP/UDP port number")
        ("thread-num,T",
         po::value<int>(&thread_num)->default_value(2),
         "Number of threads")
        ("min-depth",
         po::value<int>(&min_depth)->default_value(4),
         "Minimum ngram size")
        ("max-depth",
         po::value<int>(&max_depth)->default_value(4),
         "Minimum ngram size")
        ("verbose,v", po::value<int>()->implicit_value(1),
         "enable verbosity (optionally specify level)")
        ("out-file,o",po::value<std::string>(&out_file)->
         default_value("out.bloom"),"Output file name")
        ("pcap-file", po::value< vector<string> >(), "pcap file")
        ;

        po::positional_options_description p;
        p.add("pcap-file", -1);

         po::store(po::command_line_parser(argc, argv).
                  options(desc).positional(p).run(), vm);
        po::notify(vm);

        if (vm.count("help")) {
            cout << "Usage: options_description [options]\n";
            cout << desc;
            return 0;
        }

        if(vm.count("verbose"))
          {
            logging::core::get()->set_filter
              (
               logging::trivial::severity >= logging::trivial::debug
               );
            BOOST_LOG_TRIVIAL(info) << "Setting DEBUG" << std::endl;

          }
        else
          {
            logging::core::get()->set_filter
              (
               logging::trivial::severity >= logging::trivial::info
               );
            BOOST_LOG_TRIVIAL(info) << "Setting INFO" << std::endl;

          }

        if (vm.count("pcap-file"))
          {
            BOOST_LOG_TRIVIAL(debug) <<
              "Pcap files are: " <<
              vm["pcap-file"].as< vector<string> >() << "\n";
          }

        if (vm.count("verbose"))
          {
            BOOST_LOG_TRIVIAL(debug)  << "Verbosity enabled.  Level is " <<
              vm["verbose"].as<int>()
                                      << "\n";
          }

        if(vm.count("prob-fa"))
          {
            BOOST_LOG_TRIVIAL(debug)  << "Probability of FA " <<
              vm["prob-fa"].as<double>()
                                      << "\n";
          }
        if(vm.count("num-insertions"))
          {
            BOOST_LOG_TRIVIAL(debug)  << "Planned number of insertions " <<
              vm["num-insertions"].as<unsigned long int>()
                                      << "\n";
          }
    }
  catch(std::exception& e)
    {
      cout << e.what() << "\n";
      return 1;
    }

  // fasguard::bloom_filter_parameters
  //   *bfp_ptr = new fasguard::bloom_filter_parameters(num_insertions,pfa,
  //                                             ip_proto,port_num,min_depth,
  //                                             max_depth);

  // fasguard::bloom_filter_statistics
  //   *bfs_ptr = new fasguard::bloom_filter_statistics();

  if(merge_flag)
    {
      BloomFilterUnthreaded bf1((vm["pcap-file"].as< vector<string> >())[0],
                                false);
      BloomFilterUnthreaded bf2(vm["pcap-file"].as< vector<string> >()[1],
                                false);
      bf1.WriteCombined(bf2,out_file);
      return 0;
    }

  BloomFilterBase *bf;

  if (thread_flag)
    {
      bf = new BloomFilterThreaded(num_insertions,pfa,ip_proto,port_num,
                                   min_depth,
                                   max_depth,
                                   thread_num);
    }
  else
    {
      bf = new BloomFilterUnthreaded(num_insertions,pfa,ip_proto,port_num,
                                     min_depth,
                                     max_depth);
    }

  // BloomFilter bf(num_insertions,pfa,ip_proto,port_num,min_depth,
  //             max_depth);

  //delete bfp_ptr;
  //delete bfs_ptr;

  //bf.initialize(out_file);


  fasguard::PcapFileEngine pfe(vm["pcap-file"].as< vector<string> >(),
                           *bf,min_depth,max_depth);

  BOOST_LOG_TRIVIAL(debug)  << "Before makebloom flush " <<
    std::endl;
  bf->flush(out_file);
  delete bf;
  return 0;
}
