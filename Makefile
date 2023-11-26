.PHONY: all
all: a.out

a.out: chpasswd.o test.o
	g++ -o $@ $^ -lcrypt

chpasswd.o: chpasswd.cpp
	g++ -c -g3 -std=c++20 -Wall -Wextra -o $@ $<

test.o: test.cpp
	g++ -c -g3 -std=c++20 -Wall -Wextra -o $@ $<

.PHONY: clean
clean:
	rm -f test.o chpasswd.o a.out
