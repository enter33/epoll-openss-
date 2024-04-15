CC = g++
CFLAGS = -Wall -std=c++11
LDFLAGS = -lpcap

SRC = *.cpp
OBJ = $(SRC:.cpp=.o)
TARGET = main

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(SRC) $(LDFLAGS) -o $@

# %.o: %.cpp
# 	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET)
