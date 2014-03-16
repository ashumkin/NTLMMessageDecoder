OBJS = main.o base64.o

NTLMMessageDecoder : $(OBJS)
	CC $(OBJS) -o $@

main.o : base64.h NTLM.h

base64.o : base64.h
