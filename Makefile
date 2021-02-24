CXX = g++
LIBS = ./third-parties/mcl/lib/libmcl.a -lgmp
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
SRCS = $(wildcard src/*.cc)
OBJECTS = $(BUILD_DIR)/ps-verifier.o $(BUILD_DIR)/ps-signer.o $(BUILD_DIR)/ps-requester.o $(BUILD_DIR)/ps-encoding.o
PS_TEST_OBJECTS = $(BUILD_DIR)/ps-tests.o $(OBJECTS)
ENCODING_TEST_OBJECTS = $(BUILD_DIR)/encoding-test.o $(OBJECTS)

all: dependencies $(PROGRAMS)

.PHONY: unit-tests clean dependencies el-passo-wasm

dependencies:
	./build-dependencies.sh

debug:
	make "BUILD=debug"

$(BUILD_DIR)/%.o: %.cc
	mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(BUILD_DIR)/ps-tests: $(PS_TEST_OBJECTS)
	mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(BUILD_DIR)/encoding-tests: $(ENCODING_TEST_OBJECTS)
	mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

check: $(BUILD_DIR)/ps-tests $(BUILD_DIR)/encoding-tests
	./$(BUILD_DIR)/ps-tests
	./$(BUILD_DIR)/encoding-tests

# **********************************WASM************************************

WASM_BUILD_DIR = wasm-build

MCL_DIR = ./third-parties/mcl
EMCC = em++
EMCC_OPT = --bind -std=c++17 -Wall -Wextra -I./src -I./test -I$(MCL_DIR)/include -I$(MCL_DIR)/src
EMCC_OPT += -O3 -DNDEBUG
EMCC_OPT += -s WASM=1 -s NO_EXIT_RUNTIME=1 -s
EMCC_OPT += -s ABORTING_MALLOC=0
MCL_C_DEP = $(MCL_DIR)/src/fp.cpp $(MCL_DIR)/include/mcl/impl/bn_c_impl.hpp $(MCL_DIR)/include/mcl/bn.hpp $(MCL_DIR)/include/mcl/fp.hpp $(MCL_DIR)/include/mcl/op.hpp

$(WASM_BUILD_DIR)/wasm-tests.js : wasm-src/wasm-tests.cc $(MCL_DIR)/src/fp.cpp $(SRCS) html_template/wasm-tests.html
	mkdir -p $(@D)
	$(EMCC) -o $@ wasm-src/wasm-tests.cc $(MCL_DIR)/src/fp.cpp $(SRCS) $(EMCC_OPT) -DMCL_DONT_USE_XBYAK -DMCL_DONT_USE_OPENSSL -DMCL_USE_VINT -DMCL_SIZEOF_UNIT=8 -DMCL_VINT_64BIT_PORTABLE -DMCL_VINT_FIXED_BUFFER -DMCL_MAX_BIT_SIZE=384
	cp ./html_template/wasm-tests.html $(@D)

$(WASM_BUILD_DIR)/el-passo-idp.js : wasm-src/el-passo-idp.cc $(MCL_DIR)/src/fp.cpp $(SRCS) html_template/idp.html
	mkdir -p $(@D)
	$(EMCC) -o $@ wasm-src/el-passo-idp.cc src/ps-signer.cc src/ps-encoding.cc $(MCL_DIR)/src/fp.cpp $(EMCC_OPT) -DMCL_DONT_USE_XBYAK -DMCL_DONT_USE_OPENSSL -DMCL_USE_VINT -DMCL_SIZEOF_UNIT=8 -DMCL_VINT_64BIT_PORTABLE -DMCL_VINT_FIXED_BUFFER -DMCL_MAX_BIT_SIZE=384
	cp ./html_template/idp.html $(@D)

$(WASM_BUILD_DIR)/el-passo-rp.js : wasm-src/el-passo-rp.cc $(MCL_DIR)/src/fp.cpp $(SRCS) html_template/rp.html
	mkdir -p $(@D)
	$(EMCC) -o $@ wasm-src/el-passo-rp.cc src/ps-verifier.cc src/ps-encoding.cc $(MCL_DIR)/src/fp.cpp $(EMCC_OPT) -DMCL_DONT_USE_XBYAK -DMCL_DONT_USE_OPENSSL -DMCL_USE_VINT -DMCL_SIZEOF_UNIT=8 -DMCL_VINT_64BIT_PORTABLE -DMCL_VINT_FIXED_BUFFER -DMCL_MAX_BIT_SIZE=384
	cp ./html_template/rp.html $(@D)

$(WASM_BUILD_DIR)/el-passo-user.js : wasm-src/el-passo-user.cc $(MCL_DIR)/src/fp.cpp $(SRCS) html_template/user.html
	mkdir -p $(@D)
	$(EMCC) -o $@ wasm-src/el-passo-user.cc src/ps-requester.cc src/ps-encoding.cc $(MCL_DIR)/src/fp.cpp $(EMCC_OPT) -DMCL_DONT_USE_XBYAK -DMCL_DONT_USE_OPENSSL -DMCL_USE_VINT -DMCL_SIZEOF_UNIT=8 -DMCL_VINT_64BIT_PORTABLE -DMCL_VINT_FIXED_BUFFER -DMCL_MAX_BIT_SIZE=384
	cp ./html_template/user.html $(@D)

el-passo-wasm : dependencies $(WASM_BUILD_DIR)/el-passo-user.js $(WASM_BUILD_DIR)/el-passo-rp.js $(WASM_BUILD_DIR)/el-passo-idp.js $(WASM_BUILD_DIR)/wasm-tests.js

clean:
	rm -rf $(BUILD_DIR)

cleanjs:
	rm -rf $(WASM_BUILD_DIR)
