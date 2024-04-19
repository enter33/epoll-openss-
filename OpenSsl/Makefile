CC = g++
CFLAGS = -Wall -std=c++11
LDFLAGS = -lssl -lcrypto

SRC = main.cpp ./include/*.cpp
OBJ = $(SRC:.cpp=.o)
TARGET = main

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(SRC) $(LDFLAGS) -o $@

# %.o: %.cpp
# 	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET)