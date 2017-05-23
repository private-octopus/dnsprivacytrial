CC=gcc
CXX=g++
RM=rm -f
CPPFLAGS=-g 
LDFLAGS=-g

SRCS=pcap4dns.cpp DnsStats.cpp pcap_reader.cpp 
OBJS=$(patsubst %.cpp,%.o,$(SRCS))
DEPEND=DnsStats.h pcap_reader.h linktype.h

all: pcap4dns

pcap4dns: $(OBJS)
	$(CXX) $(LDFLAGS) -o pcap4dns $(OBJS)
 
clean:
	$(RM) $(OBJS)

distclean: clean
	$(RM) tool
