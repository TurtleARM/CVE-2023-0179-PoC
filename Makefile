objects= ./helpers.o ./exploit.o ./needle.o

.PHONY: clean needle

needle: $(objects)
	$(CC) $(objects) -lmnl -lnftnl -o needle 

./%.o: %.c
	$(CC) -c $(CFLAGS) -o "$@" "$<"
	
clean:
	rm -rf ./helpers.o ./needle.o ./needle ./exploit.o
