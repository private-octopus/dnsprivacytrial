CC=gcc
CXX=g++
RM=rm -f
CPPFLAGS=-g 
LDFLAGS=-g

SRCS=PcapSrcStats.cpp ../pcap4dns/pcap_reader.cpp
OBJS=$(patsubst %.cpp,%.o,$(SRCS))
DEPEND=../pcap4dns/pcap_reader.cpp.h

all: pcap4dns

pcap4dns: $(OBJS)
	$(CXX) $(LDFLAGS) -o pcap4dns $(OBJS)
 
clean:
	$(RM) $(OBJS)

distclean: clean
	$(RM) tool
