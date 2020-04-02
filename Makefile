CXX = g++
LIBS = -L/usr/local/opt/openssl/lib -lssl -lcrypto -L../mcl/lib -lmcl -lgmp `pkg-config --libs protobuf`
CXXFLAGS = -g -std=c++11 -Wall -I./src -I../mcl/include `pkg-config --cflags protobuf`

VPATH = ./src ./test
BUILDDIR = ./build

PROGRAMS = test_ps
OBJECTS = test_ps.o ps.o ps.pb.o nizk-schnorr.o

all: $(PROGRAMS)

protobuf: ps.proto
	protoc --cpp_out=src ps.proto

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c -o $@ $< $(LIBS)

test_ps: $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f $(OBJECTS)
	rm -f $(PROGRAMS)