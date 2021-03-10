#include <assert.h>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/PRNG.h>
#include <droidCrypto/SHA1.h>
#include <droidCrypto/SHAKE128.h>
#include <droidCrypto/ot/TwoChooseOne/KosOtExtSender.h>
#include <droidCrypto/ot/VerifiedSimplestOT.h>
#include <droidCrypto/psi/ECNRPSIServer.h>
#include <droidCrypto/utils/Log.h>
#include <droidCrypto/utils/Utils.h>
#include <endian.h>
#include <thread>
#include <fstream>

namespace droidCrypto {
    
using namespace Utils;
    
ECNRPSIServer::ECNRPSIServer(size_t num_elements, ChannelWrapper& chan, size_t num_threads /*=1*/) 
  : PhasedPSIServer{chan, num_threads},
    num_server_elements_{num_elements},
    cf_{num_server_elements_} {}
    
void ECNRPSIServer::Save(const char* path) {
    std::ofstream file;
    file.exceptions(std::ios::failbit);
    file.open(path, std::ios::trunc | std::ios::binary);
    
    auto buf = cf_.serialize();
    
    size_t buf_size = buf.size();
    
    file.write(to_char_pointer(&buf_size), sizeof(buf_size));
    
    file.write(to_char_pointer(&num_server_elements_), sizeof(num_server_elements_));
    
    file.write(to_char_pointer(buf.data()), buf.size() * sizeof(decltype(buf)::value_type));
}

ECNRPSIServer* ECNRPSIServer::FromFile(const char* path, ChannelWrapper& chan) {
    std::ifstream file;
    file.exceptions(std::ios::failbit);
    file.open(path, std::ios::binary);
    
    size_t buf_size = 0;
    file.read(to_char_pointer(&buf_size), sizeof(buf_size));
    
    size_t cf_size = 0;
    file.read(to_char_pointer(&cf_size), sizeof(cf_size));
    
    ECNRPSIServer* server = new ECNRPSIServer{cf_size, chan};
    assert(server != nullptr);
    
    std::vector<uint8_t> buf(buf_size);
    file.read(to_char_pointer(buf.data()), buf_size * sizeof(decltype(buf)::value_type));
    
    server->cf_.deserialize(buf);
    
    return server;
}

ECNRPSIServer::ECNRPSIServer(std::vector<block> &elements, ChannelWrapper& chan, size_t num_threads /*=1*/) 
  : ECNRPSIServer{elements, chan, elements.size(), num_threads} {}

ECNRPSIServer::ECNRPSIServer(std::vector<block> &elements, ChannelWrapper& chan, size_t num_elements, size_t num_threads)
  : PhasedPSIServer(chan, num_threads),
    num_server_elements_(num_elements),
    cf_(num_server_elements_) {
  time0_ = std::chrono::high_resolution_clock::now();
  size_t num_server_elements = num_server_elements_;
  std::vector<std::array<uint8_t, 33>> prfOut(num_server_elements);

  // MT-bounds
  size_t elements_per_thread = num_server_elements / num_threads_;
  Log::v("PSI", "%zu threads, %zu elements each", num_threads_,
         elements_per_thread);

  // Server-Side exponentiation
  //        std::vector<std::thread> threads;
  //        for(size_t thrd = 0; thrd < num_threads_-1; thrd++) {
  //            auto t = std::thread([&elements, elements_per_thread,idx=thrd,
  //            &prfOut, prf = prf_] {
  //                                     size_t index = idx *
  //                                     elements_per_thread;
  //
  //                                     prfOut[index], elements_per_thread);
  //                                 }
  //
  //            );
  //            threads.emplace_back(std::move(t));
  //        }
  //        //rest in main thread
  //        size_t index = (num_threads_-1)*elements_per_thread;
  //
  //        for(size_t thrd = 0; thrd < num_threads_ -1; thrd++) {
  //            threads[thrd].join();
  //        }
  for (size_t i = 0; i < num_server_elements; i++) {
    prf_.prf(elements[i]).toBytes(prfOut[i].data());
  }

  // make some space in memory
  elements.clear();

  time1_ = std::chrono::high_resolution_clock::now();
  for (size_t i = 0; i < num_server_elements; i++) {
    auto success = cf_.Add((uint64_t *)prfOut[i].data());
    (void)success;
    assert(success == cuckoofilter::Ok);
  }
  time2_ = std::chrono::high_resolution_clock::now();
  Log::v("PSI", "Built CF");
  prfOut.clear();  // free some memory
  Log::v("CF", "%s", cf_.Info().c_str());
}

void ECNRPSIServer::AddItem(block& blck) {
    std::array<uint8_t, 33> prfOut;
    prf_.prf(blck).toBytes(prfOut.data());
    auto success = cf_.Add(reinterpret_cast<uint64_t*>(prfOut.data()));
    (void) success;
    assert(success == cuckoofilter::Ok);
}

void ECNRPSIServer::Setup() {
  time3_ = std::chrono::high_resolution_clock::now();
  size_t num_server_elements = htobe64(num_server_elements_);
  channel_.send((uint8_t *)&num_server_elements, sizeof(num_server_elements));

  // send cuckoofilter in steps to save memory
  const uint64_t size_in_tags = cf_.SizeInTags();
  const uint64_t step = (1 << 16);
  uint64_t uint64_send;
  uint64_send = htobe64(size_in_tags);
  channel_.send((uint8_t *)&uint64_send, sizeof(uint64_send));
  uint64_send = htobe64(step);
  channel_.send((uint8_t *)&uint64_send, sizeof(uint64_send));

  for (uint64_t i = 0; i < size_in_tags; i += step) {
    std::vector<uint8_t> cf_ser = cf_.serialize(step, i);
    uint64_t cfsize = cf_ser.size();
    uint64_send = htobe64(cfsize);
    channel_.send((uint8_t *)&uint64_send, sizeof(uint64_send));
    channel_.send(cf_ser.data(), cfsize);
  }

  std::vector<unsigned __int128> hash_params =
      cf_.GetTwoIndependentMultiplyShiftParams();
  for (auto &par : hash_params) {
    channel_.send((uint8_t *)&par, sizeof(par));
  }

  time4_ = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> enc_time = time1_ - time0_;
  std::chrono::duration<double> cf_time = time2_ - time1_;
  std::chrono::duration<double> trans_time = time4_ - time3_;
  Log::v("PSI",
         "Setup Time:\n\t%fsec ENC, %fsec CF,\n\t%fsec Setup,\n\t%fsec "
         "Trans,\n\t Setup Comm: %fMiB sent, %fMiB recv\n",
         enc_time.count(), cf_time.count(), (enc_time + cf_time).count(),
         trans_time.count(), channel_.getBytesSent() / 1024.0 / 1024.0,
         channel_.getBytesRecv() / 1024.0 / 1024.0);
  channel_.clearStats();
}

void ECNRPSIServer::Base() {
  size_t num_client_elements;
  channel_.recv((uint8_t *)&num_client_elements, sizeof(num_client_elements));
  num_client_elements_ = be64toh(num_client_elements);
  size_t numBaseOTs = 128;
  std::vector<block> baseOTs;
  BitVector baseChoices(numBaseOTs);
  baseChoices.randomize(prng_);
  baseOTs.resize(numBaseOTs);
  span<block> baseOTsSpan(baseOTs.data(), baseOTs.size());

  VerifiedSimplestOT ot;
  ot.receive(baseChoices, baseOTsSpan, prng_, channel_);
  KosOtExtSender otExtSender;
  otExtSender.setBaseOts(baseOTsSpan, baseChoices);

  ots_.resize(num_client_elements_ * 128);
  span<std::array<block, 2>> otSpan(ots_.data(), ots_.size());
  otExtSender.send(otSpan, prng_, channel_);
}

void ECNRPSIServer::Online() {
  std::vector<std::array<uint8_t, 32>> prfInOut;
  BitVector bv(128 * num_client_elements_);

  channel_.recv(bv.data(), num_client_elements_ * 128 / 8);
  for (size_t i = 0; i < num_client_elements_; i++) {
    BitVector c;
    c.copy(bv, 128 * i, 128);
    span<std::array<block, 2>> otSpan(&ots_[i * 128], 128);
    prf_.oprf(c, otSpan, channel_);
  }
}
}  // namespace droidCrypto
