CXX = g++
LIBS = -L../mcl/lib -lmcl `pkg-config --libs protobuf`
CXXFLAGS = -I../mcl/include `pkg-config --cflags protobuf`

PROGRAMS = test_ps

all: $(PROGRAMS)

protobuf: ps.proto
	protoc --cpp_out=src ps.proto

%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

%.o: %.cc
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

test_ps: ps.o ps.pb.o test_ps.o
	$(CC) $(CXXFLAGS) -o $@ $^ $(LIBS)