#pragma once

#include <droidCrypto/psi/PhasedPSIServer.h>
#include <droidCrypto/gc/circuits/LowMCCircuit.h>
#include <droidCrypto/lowmc/lowmc.h>
#include "cuckoofilter/cuckoofilter.h"

namespace droidCrypto {

class OPRFLowMCPSIServer : public PhasedPSIServer {
    typedef cuckoofilter::CuckooFilter<uint64_t*, 32, cuckoofilter::SingleTable,
            cuckoofilter::TwoIndependentMultiplyShift128> CuckooFilter;
 public:
 
  OPRFLowMCPSIServer(size_t num_elements, ChannelWrapper& chan, size_t num_threads = 1);
  
  OPRFLowMCPSIServer(std::vector<block> &elements, ChannelWrapper& chan, size_t num_threads = 1);
  
  OPRFLowMCPSIServer(std::vector<block> &elements, ChannelWrapper& chan, size_t num_elements, size_t num_threads);

  void Setup() override;

  void Base() override;

  void Online() override;
  
  void AddItem(block&) override;
  
  void Save(const char* path) override;
  
  static OPRFLowMCPSIServer* FromFile(const char*, ChannelWrapper&);

 private:
 
  static void InitKey(OPRFLowMCPSIServer&);
  
  size_t num_server_elements_;
  CuckooFilter cf_;
  const lowmc_t* params_;
  std::array<uint8_t, 16> lowmc_key_;
  SIMDLowMCCircuitPhases circ_;
  expanded_key expanded_key_;
  
  std::chrono::time_point<std::chrono::high_resolution_clock> 
  time0_, time1_, time2_, time3_, time4_;
};

}

