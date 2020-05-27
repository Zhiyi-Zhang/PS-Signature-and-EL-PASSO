CXX = g++
LIBS = -L./third-parties/mcl/lib -lgmp -lmcl -lprotobuf
CXXFLAGS = -std=c++17 -Wall -I./src -I./third-parties/mcl/include -DMCL_DONT_USE_OPENSSL -I/usr/local/include

ifeq ($(BUILD),debug)
# "Debug" build - no optimization, and debugging symbols
CXXFLAGS += -g
else
# "Release" build - optimization, and no debug symbols
CXXFLAGS += -O3 -DNDEBUG
endif

VPATH = ./src ./test
BUILD_DIR = build

PROGRAMS = $(BUILD_DIR)/ps-tests $(BUILD_DIR)/encoding-tests
SRCS = $(wildcard src/*.cpp)
OBJECTS = $(BUILD_DIR)/ps-tests.o $(BUILD_DIR)/ps-verifier.o $(BUILD_DIR)/ps-signer.o $(BUILD_DIR)/ps-requester.o
OBJECTS_PROTOBUF = $(BUILD_DIR)/encoding-test.o $(BUILD_DIR)/ps.pb.o $(BUILD_DIR)/protobuf-encoding.o $(BUILD_DIR)/ps-verifier.o $(BUILD_DIR)/ps-signer.o $(BUILD_DIR)/ps-requester.o

all: $(PROGRAMS)

.PHONY: unit-tests clean mcl emar_mcl el-pass-wasm

mcl:
	./install-mcl.sh

protobuf: src/ps.proto
	protoc --proto_path=src --cpp_out=src src/ps.proto

debug:
	make "BUILD=debug"

$(BUILD_DIR)/%.o: %.cc
	mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(BUILD_DIR)/ps-tests: $(OBJECTS) $(SRCS)
	mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(BUILD_DIR)/encoding-tests: $(OBJECTS_PROTOBUF) $(SRCS)
	mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

# **********************************WASM************************************

WASM_BUILD_DIR = wasm-build

MCL_DIR = ./third-parties/mcl
EMCC = em++
EMCC_OPT = --bind -std=c++17 -Wall -Wextra -I./src -I./test -I$(MCL_DIR)/include -I$(MCL_DIR)/src
EMCC_OPT += -O3 -DNDEBUG
EMCC_OPT += -s WASM=1 -s NO_EXIT_RUNTIME=1 -s
EMCC_OPT += -s ABORTING_MALLOC=0
MCL_C_DEP = $(MCL_DIR)/src/fp.cpp $(MCL_DIR)/include/mcl/impl/bn_c_impl.hpp $(MCL_DIR)/include/mcl/bn.hpp $(MCL_DIR)/include/mcl/fp.hpp $(MCL_DIR)/include/mcl/op.hpp

$(WASM_BUILD_DIR)/ps.js : src/ps.cc $(MCL_DIR)/src/fp.cpp
	mkdir -p $(@D)
	$(EMCC) -o $@ $(MCL_DIR)/src/fp.cpp src/ps.cc $(EMCC_OPT) -DMCL_DONT_USE_XBYAK -DMCL_DONT_USE_OPENSSL -DMCL_USE_VINT -DMCL_SIZEOF_UNIT=8 -DMCL_VINT_64BIT_PORTABLE -DMCL_VINT_FIXED_BUFFER -DMCL_MAX_BIT_SIZE=384

$(WASM_BUILD_DIR)/ps-tests.js : test-wasm/ps-tests.cc $(MCL_DIR)/src/fp.cpp $(SRCS)
	mkdir -p $(@D)
	$(EMCC) -o $@ test-wasm/ps-tests.cc $(MCL_DIR)/src/fp.cpp src/ps-signer.cc src/ps-verifier.cc src/ps-requester.cc $(EMCC_OPT) -DMCL_DONT_USE_XBYAK -DMCL_DONT_USE_OPENSSL -DMCL_USE_VINT -DMCL_SIZEOF_UNIT=8 -DMCL_VINT_64BIT_PORTABLE -DMCL_VINT_FIXED_BUFFER -DMCL_MAX_BIT_SIZE=384

$(WASM_BUILD_DIR)/ps-tests.html : test-wasm/ps-tests.cc $(MCL_DIR)/src/fp.cpp $(SRCS)
	mkdir -p $(@D)
	$(EMCC) -o $@ test-wasm/ps-tests.cc $(MCL_DIR)/src/fp.cpp src/ps-signer.cc src/ps-verifier.cc src/ps-requester.cc $(EMCC_OPT) -DMCL_DONT_USE_XBYAK -DMCL_DONT_USE_OPENSSL -DMCL_USE_VINT -DMCL_SIZEOF_UNIT=8 -DMCL_VINT_64BIT_PORTABLE -DMCL_VINT_FIXED_BUFFER -DMCL_MAX_BIT_SIZE=384 --shell-file html_template/shell_minimal.html -s "EXTRA_EXPORTED_RUNTIME_METHODS=['ccall']"
	cp ./html_template/ps-tests.html $(@D)

$(WASM_BUILD_DIR)/el-passo-idp.js : test-wasm/el-passo-idp.cc $(MCL_DIR)/src/fp.cpp $(SRCS)
	mkdir -p $(@D)
	$(EMCC) -o $@ test-wasm/el-passo-idp.cc src/ps-signer.cc $(MCL_DIR)/src/fp.cpp $(EMCC_OPT) -DMCL_DONT_USE_XBYAK -DMCL_DONT_USE_OPENSSL -DMCL_USE_VINT -DMCL_SIZEOF_UNIT=8 -DMCL_VINT_64BIT_PORTABLE -DMCL_VINT_FIXED_BUFFER -DMCL_MAX_BIT_SIZE=384

$(WASM_BUILD_DIR)/el-passo-rp.js : test-wasm/el-passo-rp.cc $(MCL_DIR)/src/fp.cpp $(SRCS)
	mkdir -p $(@D)
	$(EMCC) -o $@ test-wasm/el-passo-rp.cc src/ps-verifier.cc $(MCL_DIR)/src/fp.cpp $(EMCC_OPT) -DMCL_DONT_USE_XBYAK -DMCL_DONT_USE_OPENSSL -DMCL_USE_VINT -DMCL_SIZEOF_UNIT=8 -DMCL_VINT_64BIT_PORTABLE -DMCL_VINT_FIXED_BUFFER -DMCL_MAX_BIT_SIZE=384

$(WASM_BUILD_DIR)/el-passo-user.js : test-wasm/el-passo-user.cc $(MCL_DIR)/src/fp.cpp $(SRCS)
	mkdir -p $(@D)
	$(EMCC) -o $@ test-wasm/el-passo-user.cc src/ps-requester.cc $(MCL_DIR)/src/fp.cpp $(EMCC_OPT) -DMCL_DONT_USE_XBYAK -DMCL_DONT_USE_OPENSSL -DMCL_USE_VINT -DMCL_SIZEOF_UNIT=8 -DMCL_VINT_64BIT_PORTABLE -DMCL_VINT_FIXED_BUFFER -DMCL_MAX_BIT_SIZE=384

el-pass-wasm : $(WASM_BUILD_DIR)/el-passo-user.js $(WASM_BUILD_DIR)/el-passo-rp.js $(WASM_BUILD_DIR)/el-passo-idp.js $(WASM_BUILD_DIR)/ps-tests.html

clean:
	rm -rf build

cleanjs:
	rm -f *.js *.wasm *.html *.bc
