CC = gcc
LD = gcc
CFLAGS = -Wall
#CFLAGS = -Wall -g
LDFLAGS = -levent_core

EXE = ffmpjpeg-httpd
SRC = $(wildcard *.c)
OBJ = $(patsubst %.c,build/%.o,$(SRC))

$(EXE): $(OBJ)
	$(LD) -o $@ $^ $(LDFLAGS)

-include $(OBJ:.o=.d)

$(OBJ): build/%.o : %.c
	$(CC) $(CFLAGS) -c $< -o build/$*.o
	@$(CC) $(CFLAGS) -MM $< -MF build/$*.d
	@sed -i build/$*.d -e 's,\($*\)\.o[ :]*,build/\1.o: ,g'

clean:
	rm -rf $(EXE) build/*.o build/*.d
