#Makefile
CC=gcc
INCLUDE=
LIB=-lpthread -lcrypto
CFLAGS=-g -Wall -Werror -D_REENTRANT -D_GNU_SOURCE ${LIB} ${INCLUDE}
OutPut=myPing
src:=$(wildcard ./*.c)
target:=$(patsubst %.c, %.o, ${src})
springcleaning+=$(OutPut)

.PHONY: all clean

all: $(OutPut)
$(OutPut):${target}
	$(CC) ${target}  -o $@ ${CFLAGS} ${INCLUDE} 
	
clean:
	-@rm  ${springcleaning}
