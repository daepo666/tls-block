TARGET = tls-block
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17
LDLIBS = -lpcap

SRCS = main.cpp tls_block.cpp

all: $(TARGET)

$(TARGET): $(SRCS) tls_block.h my_struct.h
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS) $(LDLIBS)

clean:
	rm -f $(TARGET)