TARGET = libprejailbreak.dylib
CC = clang

CFLAGS = -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -miphoneos-version-min=12.0 -fobjc-arc -dynamiclib -install_name @loader_path/$(TARGET) -framework IOSurface -framework IOKit
LDFLAGS = 

sign: $(TARGET)
	ldid -S build/$<

$(TARGET): $(wildcard src/*.c src/*.m src/*.S)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
	mkdir -p build
	mkdir -p include
	mkdir -p include/libprejailbreak
	cp src/*.h include/libprejailbreak
	mv $@ build

clean:
	rm -f $(TARGET)
	rm -rf build
	rm -rf include