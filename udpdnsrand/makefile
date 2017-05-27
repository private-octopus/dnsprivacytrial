CC=gcc
CXX=g++
RM=rm -f
CPPFLAGS=-g 
LDFLAGS=-g

SRCS=DnsGenRandom.cpp RandGen.cpp DomainList.cpp udpdnsrand.cpp 
OBJS=$(patsubst %.cpp,%.o,$(SRCS))
DEPEND=DnsGenRandom.h RandGen.h DomainList.h HashWriteOnceGeneric.h

all: udpdnsrand

udpdnsrand: $(OBJS)
	$(CXX) $(LDFLAGS) -o pcap4dns $(OBJS)
 
clean:
	$(RM) $(OBJS)

distclean: clean
	$(RM) tool
