#include <droidCrypto/psi/OPRFLowMCPSIServer.h>
#include <droidCrypto/ChannelWrapper.h>
#include <droidCrypto/gc/circuits/LowMCCircuit.h>
#include <thread>
#include <fstream>
#include <assert.h>
#include <endian.h>
#include <droidCrypto/utils/Log.h>
#include <droidCrypto/utils/Utils.h>

extern "C" {
#include <droidCrypto/lowmc/lowmc_pars.h>
#include <droidCrypto/lowmc/io.h>
#include <droidCrypto/lowmc/lowmc_128_128_192.h>
}

namespace droidCrypto {
    
using namespace Utils;
    
OPRFLowMCPSIServer::OPRFLowMCPSIServer(size_t num_elements, ChannelWrapper& chan, size_t num_threads /*=1*/)
  : PhasedPSIServer{chan, num_threads},
    num_server_elements_{num_elements},
    cf_{num_server_elements_},
    circ_{chan} {}

OPRFLowMCPSIServer::OPRFLowMCPSIServer(std::vector<block>& elements, ChannelWrapper& chan, size_t num_threads)
  : OPRFLowMCPSIServer{elements, chan, elements.size(), num_threads} {}

OPRFLowMCPSIServer::OPRFLowMCPSIServer(std::vector<block>& elements, ChannelWrapper& chan, size_t num_elements, size_t num_threads /*=1*/)
  : PhasedPSIServer(chan, num_threads), 
    num_server_elements_(num_elements), 
    cf_(num_server_elements_), 
    circ_(chan)
{
    time0_ = std::chrono::high_resolution_clock::now();
    
    // get a random key
    PRNG::getTestPRNG().get(lowmc_key_.data(), lowmc_key_.size());
    
    InitKey(*this);
    
    size_t num_server_elements = num_server_elements_;
    //MT-bounds
    size_t elements_per_thread = num_server_elements / num_threads_;
    Log::v("PSI", "%zu threads, %zu elements each", num_threads_, elements_per_thread);

    std::vector<std::thread> threads;
    for(size_t thrd = 0; thrd < num_threads_-1; thrd++) {
        auto t = std::thread([this, &elements, elements_per_thread,idx=thrd]{
            lowmc_key_t* pt = mzd_local_init(1, params_->n);
            for(size_t i = idx*elements_per_thread; i < (idx+1)*elements_per_thread; i++) {
                mzd_from_char_array(pt, (uint8_t *) (&elements[i]), params_->n / 8);
                mzd_local_t *ct = lowmc_call(params_, expanded_key_, pt);
                mzd_to_char_array((uint8_t *) (&elements[i]), ct, params_->n / 8);
                mzd_local_free(ct);
            }
            mzd_local_free(pt);
        });
        threads.emplace_back(std::move(t));
    }
    lowmc_key_t* pt = mzd_local_init(1, params_->n);
    for(size_t i = (num_threads_-1)*elements_per_thread; i < num_server_elements; i++) {
        mzd_from_char_array(pt, (uint8_t *) (&elements[i]), params_->n / 8);
        mzd_local_t *ct = lowmc_call(params_, expanded_key_, pt);
        mzd_to_char_array((uint8_t *) (&elements[i]), ct, (params_->n) / 8);
        mzd_local_free(ct);
    }
    mzd_local_free(pt);
    for(size_t thrd = 0; thrd < num_threads_ -1; thrd++) {
        threads[thrd].join();
    }

    time1_ = std::chrono::high_resolution_clock::now();

    for(size_t i = 0; i < num_server_elements; i++) {
        auto success = cf_.Add((uint64_t*)&elements[i]);
        (void) success;
        assert(success == cuckoofilter::Ok);
    }
    Log::v("PSI", "Built CF");
    elements.clear(); // free some memory
    Log::v("CF", "%s", cf_.Info().c_str());
}

void OPRFLowMCPSIServer::Save(const char* path) {
    std::ofstream file;
    file.exceptions(std::ios::failbit);
    file.open(path, std::ios::trunc | std::ios::binary);
    
    auto buf = cf_.serialize();
    
    size_t buf_size = buf.size();
    
    file.write(to_char_pointer(&buf_size), sizeof(buf_size));
    
    file.write(to_char_pointer(&num_server_elements_), sizeof(num_server_elements_));
    
    file.write(to_char_pointer(lowmc_key_.data()), lowmc_key_.size());
    
    file.write(to_char_pointer(buf.data()), buf.size() * sizeof(decltype(buf)::value_type));
}

OPRFLowMCPSIServer* OPRFLowMCPSIServer::FromFile(const char* path, ChannelWrapper& chan) {
    std::ifstream file;
    file.exceptions(std::ios::failbit);
    file.open(path, std::ios::binary);
    
    size_t buf_size = 0;
    file.read(to_char_pointer(&buf_size), sizeof(buf_size));
    
    size_t cf_size = 0;
    file.read(to_char_pointer(&cf_size), sizeof(cf_size));
    
    OPRFLowMCPSIServer* server = new OPRFLowMCPSIServer{cf_size, chan};
    assert(server != nullptr);
    
    server->params_ = SIMDLowMCCircuitPhases::params;
    file.read(to_char_pointer(server->lowmc_key_.data()), server->lowmc_key_.size());
    
    InitKey(*server);
    
    std::vector<uint8_t> buf(buf_size);
    file.read(to_char_pointer(buf.data()), buf_size * sizeof(decltype(buf)::value_type));
    
    server->cf_.deserialize(buf);
    
    return server;
}

void OPRFLowMCPSIServer::InitKey(OPRFLowMCPSIServer& server) {
    //LOWMC encryption
    server.params_ = SIMDLowMCCircuitPhases::params;
    lowmc_key_t* key = mzd_local_init(1, server.params_->k);
    mzd_from_char_array(key, server.lowmc_key_.data(), (server.params_->k)/8);
    server.expanded_key_ = lowmc_expand_key(server.params_, key);
}

void OPRFLowMCPSIServer::AddItem(block& blck) {
    lowmc_key_t* pt = mzd_local_init(1, params_->n);
    mzd_from_char_array(pt, reinterpret_cast<uint8_t *>(&blck), params_->n / 8);
    mzd_local_t *ct = lowmc_call(params_, expanded_key_, pt);
    mzd_to_char_array(reinterpret_cast<uint8_t*>(&blck), ct, (params_->n) / 8);
    mzd_local_free(ct);
    mzd_local_free(pt);
    auto success = cf_.Add(reinterpret_cast<uint64_t*>(&blck));
    (void) success;
    assert(success == cuckoofilter::Ok);
}

void OPRFLowMCPSIServer::Setup() {
    time3_ = std::chrono::high_resolution_clock::now();

    size_t num_server_elements = htobe64(num_server_elements_);
    channel_.send((uint8_t*)&num_server_elements, sizeof(num_server_elements));

    //send cuckoofilter in steps to save memory
    const uint64_t size_in_tags = cf_.SizeInTags();
    const uint64_t step = (1<<16);
    uint64_t uint64_send;
    uint64_send = htobe64(size_in_tags);
    channel_.send((uint8_t *) &uint64_send, sizeof(uint64_send));
    uint64_send = htobe64(step);
    channel_.send((uint8_t *) &uint64_send, sizeof(uint64_send));

    for(uint64_t i = 0; i < size_in_tags; i+=step) {
        std::vector<uint8_t> cf_ser = cf_.serialize(step, i);
        uint64_t cfsize = cf_ser.size();
        uint64_send = htobe64(cfsize);
        channel_.send((uint8_t *) &uint64_send, sizeof(uint64_send));
        channel_.send(cf_ser.data(), cfsize);
    }

    std::vector<unsigned __int128> hash_params = cf_.GetTwoIndependentMultiplyShiftParams();
    for(auto& par : hash_params) {
        channel_.send((uint8_t*)&par, sizeof(par));
    }

    time4_ = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> enc_time = time1_ - time0_;
    std::chrono::duration<double> cf_time = time2_ - time1_;
    std::chrono::duration<double> trans_time = time4_ - time3_;
    Log::v("PSI", "Setup Time:\n\t%fsec ENC, %fsec CF,\n\t%fsec Setup,\n\t%fsec Trans,\n\t Setup Comm: %fMiB sent, %fMiB recv\n",
           enc_time.count(), cf_time.count(), (enc_time+cf_time).count(), trans_time.count(), channel_.getBytesSent()/1024.0/1024.0, channel_.getBytesRecv()/1024.0/1024.0);
    channel_.clearStats();
}

void OPRFLowMCPSIServer::Base() {
    size_t num_client_elements;
    channel_.recv((uint8_t*)&num_client_elements, sizeof(num_client_elements));
    num_client_elements = be64toh(num_client_elements);

    droidCrypto::BitVector key_bits(lowmc_key_.data(),
                                    droidCrypto::SIMDLowMCCircuitPhases::params->n);
    circ_.garbleBase(key_bits, num_client_elements);
}

void OPRFLowMCPSIServer::Online() {
    circ_.garbleOnline();
    //done on server side
}

}