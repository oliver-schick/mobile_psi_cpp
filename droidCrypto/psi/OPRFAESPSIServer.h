#pragma once

#include <droidCrypto/psi/PhasedPSIServer.h>
#include <droidCrypto/gc/circuits/AESCircuit.h>
#include "cuckoofilter/cuckoofilter.h"

namespace droidCrypto {
class OPRFAESPSIServer : public PhasedPSIServer {
  typedef cuckoofilter::CuckooFilter<
      uint64_t *, 32, cuckoofilter::SingleTable,
      cuckoofilter::TwoIndependentMultiplyShift128>
      CuckooFilter;
 public:
  OPRFAESPSIServer(std::vector<block> &elements, ChannelWrapper& chan, size_t num_threads = 1);

  void Setup() override;

  void Base() override;

  void Online() override;
  
  void AddItem(block&) override;
  
  void Save(const char*) override;

 private:
  size_t num_server_elements_;
  CuckooFilter cf_;
  SIMDAESCircuitPhases circ_;
  
  std::chrono::time_point<std::chrono::high_resolution_clock> 
  time0_, time1_, time2_, time3_, time4_;
};

}

