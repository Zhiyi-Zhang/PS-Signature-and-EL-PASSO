CXX = g++
LIBS = -L./third-parties/mcl/lib -lgmp -lmcl -lprotobuf
CXXFLAGS = -g -std=c++17 -Wall -I./src -I./third-parties/mcl/include -DMCL_DONT_USE_OPENSSL -I/usr/local/include

VPATH = ./src ./test
BUILDDIR = ./build

PROGRAMS = unit_tests
OBJECTS = unit_tests.o ps.o ps.pb.o nizk-schnorr.o
BC_OBJECTS = wasm_test_nizk.bc nizk-schnorr.bc

all: $(PROGRAMS)

.PHONY: clean mcl emar_mcl

mcl:
	./install-mcl.sh

protobuf: ps.proto
	protoc --cpp_out=src ps.proto

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c -o $@ $<

unit_tests: $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

# **********************************WASM************************************

MCL_DIR = ./third-parties/mcl
EMCC = em++
EMCC_OPT = -I./src -I./test -I$(MCL_DIR)/include -I$(MCL_DIR)/src -Wall -Wextra
EMCC_OPT += -O3 -DNDEBUG -DMCLSHE_WIN_SIZE=8
EMCC_OPT += -s WASM=1 -s NO_EXIT_RUNTIME=1 -s MODULARIZE=1
EMCC_OPT += -DCYBOZU_MINIMUM_EXCEPTION
EMCC_OPT += -s ABORTING_MALLOC=0
MCL_C_DEP = $(MCL_DIR)/src/fp.cpp $(MCL_DIR)/include/mcl/impl/bn_c_impl.hpp $(MCL_DIR)/include/mcl/bn.hpp $(MCL_DIR)/include/mcl/fp.hpp $(MCL_DIR)/include/mcl/op.hpp

bls12_381.bc: wasm/bls12-381.cpp $(MCL_C_DEP)
	emcc -c -o $@ wasm/bls12-381.cpp $(EMCC_OPT) -DMCL_MAX_BIT_SIZE=256 -DMCL_USE_WEB_CRYPTO_API -s DISABLE_EXCEPTION_CATCHING=1 -DCYBOZU_DONT_USE_EXCEPTION -DCYBOZU_DONT_USE_STRING -fno-exceptions

fp.bc: wasm/bls12-381.cpp $(MCL_C_DEP)
	emcc -c -o $@ $(MCL_DIR)/src/fp.cpp $(EMCC_OPT) -DMCL_MAX_BIT_SIZE=256 -DMCL_USE_WEB_CRYPTO_API -s DISABLE_EXCEPTION_CATCHING=1 -DCYBOZU_DONT_USE_EXCEPTION -DCYBOZU_DONT_USE_STRING -fno-exceptions

%.bc: %.cc
	$(EMCC) $(EMCC_OPT) -c -o $@ $<

wasm_test_nizk.js : bls12_381.bc fp.bc $(BC_OBJECTS)
	$(EMCC) $(EMCC_OPT) fp.bc bls12_381.bc -o $@ $^

clean:
	rm -f $(OBJECTS)
	rm -f $(JS_OBJECTS)
	rm -f *.bc
	rm -f *.o
	rm -f $(PROGRAMS)