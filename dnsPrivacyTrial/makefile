CC=gcc
CXX=g++
RM=rm -f
CPPFLAGS=-g 
LDFLAGS=-g

SRCS=dnsPrivacyTrial.cpp CdnParser.cpp DnsDissectorLine.cpp DnsTraces.cpp DnsTracesUtil.cpp DnsTransaction.cpp  
OBJS=$(patsubst %.cpp,%.o,$(SRCS))
DEPEND= CdnParser.h DnsDissectorLine.h DnsTraces.h DnsTracesUtil.h DnsTransaction.h DnsTypes.h

all: dnsPrivacyTrial 

dnsPrivacyTrial: $(OBJS)
	$(CXX) $(LDFLAGS) -o dnsPrivacyTrial $(OBJS)
 
clean:
	$(RM) $(OBJS)

distclean: clean
	$(RM) tool
