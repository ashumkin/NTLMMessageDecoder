OBJS = main.o base64.o
CFLAGS=-g

NTLMMessageDecoder : $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@

main.o : base64.h NTLM.h

base64.o : base64.h
