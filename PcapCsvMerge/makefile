CC=gcc
CXX=g++
RM=rm -f
CPPFLAGS=-g 
LDFLAGS=-g

SRCS=PcapCsvMerge.cpp PcapCsvReader.cpp
OBJS=$(patsubst %.cpp,%.o,$(SRCS))
DEPEND=PcapCsvReader.h

all: PcapCsvMerge 

PcapCsvMerge: $(OBJS)
	$(CXX) $(LDFLAGS) -o PcapCsvMerge $(OBJS) 
 
clean:
	$(RM) $(OBJS)

distclean: clean
	$(RM) tool
