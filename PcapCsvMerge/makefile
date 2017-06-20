CC=gcc
CXX=g++
RM=rm -f
CPPFLAGS=-g 
LDFLAGS=-g

SRCS=PcapCsvMerge.cpp PcapCsvReader.cpp
OBJS=$(patsubst %.cpp,%.o,$(SRCS))
DEPEND=PcapCsvReader.h

all: pcap4dns

pcap4dns: $(OBJS)
	$(CXX) $(LDFLAGS) -o pcap4dns $(OBJS)
 
clean:
	$(RM) $(OBJS)

distclean: clean
	$(RM) tool
