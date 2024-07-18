CXX = clang++
CXXFLAGS = -DNDEBUG -fsanitize=address,undefined -fno-omit-frame-pointer -g -O2 -std=c++11
LDFLAGS = -fsanitize=address,undefined

TARGET = dnp3_listener
SOURCES = main.cc DNP3.cc

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)

.PHONY: clean run

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
