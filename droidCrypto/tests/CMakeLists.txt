cmake_minimum_required(VERSION 3.4.1)
if ("${ANDROID}")
else ()
  set(TEST_SRCS
    test_gc_aes.cpp
    test_gc_lowmc.cpp
    test_gc_lowmc_phased.cpp
    test_ot_base.cpp
    test_ot_dot.cpp
    test_ot_kos.cpp
    test_psi_oprf_lowmc.cpp
    test_psi_oprf_ecnr.cpp
    test_speed.cpp
    )
  foreach (filename ${TEST_SRCS})
    get_filename_component(testname ${filename} NAME_WE)
    add_executable(${testname} ${filename})
    target_link_libraries(${testname} droidcrypto pthread)
  endforeach ()
  
  function(test_psi psi_target)
    get_target_property(TEST_DIR ${psi_target} BINARY_DIR)
    get_target_property(TEST_NAME ${psi_target} NAME)
    add_test(NAME ${psi_target} 
             COMMAND sh -c "${TEST_DIR}/${TEST_NAME} 0 20 & ${TEST_DIR}/${TEST_NAME} 1 10")
  endfunction()
  
  add_test(NAME test_gc_aes COMMAND test_gc_aes)
  add_test(NAME test_gc_lowmc COMMAND test_gc_lowmc)
  add_test(NAME test_gc_lowmc_phased COMMAND test_gc_lowmc_phased)
  add_test(NAME test_ot_base COMMAND test_ot_dot)
  add_test(NAME test_ot_kos COMMAND test_ot_kos)
  test_psi(test_psi_oprf_lowmc)
  test_psi(test_psi_oprf_ecnr)
  
endif ()



