.PHONY: clean

CC = clang
STD = c17
FILE = prog

${FILE}.out:
	$(CC) -std=$(STD) -o $(FILE).out $(FILE).c

clean:
	rm $(FILE).out
