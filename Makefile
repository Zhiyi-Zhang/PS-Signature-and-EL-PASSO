CXX = g++
LIBS = -L/usr/local/opt/openssl/lib -lssl -lcrypto -L../mcl/lib -lmcl -lgmp `pkg-config --libs protobuf`
CXXFLAGS = -g -std=c++17 -Wall -I./src -I../mcl/include `pkg-config --cflags protobuf`

VPATH = ./src ./test
BUILDDIR = ./build

PROGRAMS = unit_tests
OBJECTS = unit_tests.o ps.o ps.pb.o nizk-schnorr.o

all: $(PROGRAMS)

protobuf: ps.proto
	protoc --cpp_out=src ps.proto

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c -o $@ $< $(LIBS)

unit_tests: $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f $(OBJECTS)
	rm -f $(PROGRAMS)