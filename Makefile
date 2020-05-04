CXX = g++
LIBS = -L./third-parties/mcl/lib -lgmp -lmcl -lprotobuf
CXXFLAGS = -g -std=c++17 -Wall -I./src -I./third-parties/mcl/include -DMCL_DONT_USE_OPENSSL -I/usr/local/include

VPATH = ./src ./test
BUILDDIR = ./build

PROGRAMS = ps-tests encoding-tests
OBJECTS = ps-tests.o ps.o
OBJECTS_PROTOBUF = encoding-test.o ps.pb.o ps.o protobuf-encoding.o

all: $(PROGRAMS)

.PHONY: unit-tests clean mcl emar_mcl

mcl:
	./install-mcl.sh

protobuf: ps.proto
	protoc --cpp_out=src ps.proto

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c -o $@ $<

unit-tests: $(PROGRAMS)

ps-tests: $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

encoding-tests: $(OBJECTS_PROTOBUF)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

# **********************************WASM************************************

MCL_DIR = ./third-parties/mcl
EMCC = em++
EMCC_OPT = -I./src -I./test -I$(MCL_DIR)/include -I$(MCL_DIR)/src -Wall -Wextra
EMCC_OPT += -O3 -DNDEBUG
EMCC_OPT += -s WASM=1 -s NO_EXIT_RUNTIME=1 -s # MODULARIZE=1
# EMCC_OPT += -DCYBOZU_MINIMUM_EXCEPTION
EMCC_OPT += -s ABORTING_MALLOC=0
MCL_C_DEP = $(MCL_DIR)/src/fp.cpp $(MCL_DIR)/include/mcl/impl/bn_c_impl.hpp $(MCL_DIR)/include/mcl/bn.hpp $(MCL_DIR)/include/mcl/fp.hpp $(MCL_DIR)/include/mcl/op.hpp

# bls12_381.bc:  $(MCL_C_DEP)
# 	emcc -c -o $@ wasm/bls12-381.cpp $(EMCC_OPT) -DMCL_MAX_BIT_SIZE=256 -DMCL_USE_WEB_CRYPTO_API -s DISABLE_EXCEPTION_CATCHING=1 -DCYBOZU_DONT_USE_EXCEPTION -DCYBOZU_DONT_USE_STRING -fno-exceptions

# fp.bc: wasm/bls12-381.cpp $(MCL_C_DEP)
# 	emcc -c -o $@ $(MCL_DIR)/src/fp.cpp $(EMCC_OPT) -DMCL_MAX_BIT_SIZE=256 -DMCL_USE_WEB_CRYPTO_API -s DISABLE_EXCEPTION_CATCHING=1 -DCYBOZU_DONT_USE_EXCEPTION -DCYBOZU_DONT_USE_STRING -fno-exceptions

# %.bc: %.cc
# 	$(EMCC) $(EMCC_OPT) -c -o $@ $<

ps.js : src/ps.cc $(MCL_DIR)/src/fp.cpp
	$(EMCC) -o $@ $(MCL_DIR)/src/fp.cpp src/ps.cc $(EMCC_OPT) -DMCL_DONT_USE_XBYAK -DMCL_DONT_USE_OPENSSL -DMCL_USE_VINT -DMCL_SIZEOF_UNIT=8 -DMCL_VINT_64BIT_PORTABLE -DMCL_VINT_FIXED_BUFFER -DMCL_MAX_BIT_SIZE=384

ps-tests.js : test/ps-tests.cc $(MCL_DIR)/src/fp.cpp
	$(EMCC) -o $@ test/ps-tests.cc $(MCL_DIR)/src/fp.cpp src/ps.cc $(EMCC_OPT) -DMCL_DONT_USE_XBYAK -DMCL_DONT_USE_OPENSSL -DMCL_USE_VINT -DMCL_SIZEOF_UNIT=8 -DMCL_VINT_64BIT_PORTABLE -DMCL_VINT_FIXED_BUFFER -DMCL_MAX_BIT_SIZE=384

ps-tests.html : test/ps-tests.cc $(MCL_DIR)/src/fp.cpp
	$(EMCC) -o $@ test/ps-tests.cc $(MCL_DIR)/src/fp.cpp src/ps.cc $(EMCC_OPT) -DMCL_DONT_USE_XBYAK -DMCL_DONT_USE_OPENSSL -DMCL_USE_VINT -DMCL_SIZEOF_UNIT=8 -DMCL_VINT_64BIT_PORTABLE -DMCL_VINT_FIXED_BUFFER -DMCL_MAX_BIT_SIZE=384

clean:
	rm -f $(OBJECTS)
	rm -f *.bc *.o
	rm -f js.wasm
	rm -f $(PROGRAMS)
