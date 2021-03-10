#pragma once

#include <chrono>

#include <droidCrypto/psi/PhasedPSIServer.h>
#include <droidCrypto/psi/tools/ECNRPRF.h>
#include "cuckoofilter/cuckoofilter.h"

namespace droidCrypto {
    
class ChannelWrapper;

class ECNRPSIServer : public PhasedPSIServer {
  typedef cuckoofilter::CuckooFilter<
      uint64_t *, 32, cuckoofilter::SingleTable,
      cuckoofilter::TwoIndependentMultiplyShift256>
      CuckooFilter;
 public:
  ECNRPSIServer(size_t num_elements, ChannelWrapper& chan, size_t num_threads = 1);
  
  ECNRPSIServer(std::vector<block> &elements, ChannelWrapper &chan, size_t num_threads = 1);
  
  ECNRPSIServer(std::vector<block> &elements, ChannelWrapper &chan, size_t num_elements, size_t num_threads);

  void Setup() override;
  void Base() override;
  void Online() override;
  void AddItem(block&) override;
  void Save(const char*) override;
  
  static ECNRPSIServer* FromFile(const char* path, ChannelWrapper& chan);

 private:
  size_t num_server_elements_;
  CuckooFilter cf_;
  PRNG prng_{PRNG::getTestPRNG()};
  ECNRPRF prf_{prng_, 128};
  size_t num_client_elements_ = 0;
  std::vector<std::array<block, 2>> ots_;
  
  std::chrono::time_point<std::chrono::high_resolution_clock> 
  time0_, time1_, time2_, time3_, time4_;
};

}  // namespace droidCrypto
