SHELL := /bin/bash

.SILENT:

hello:
	source hello.sh && \
	if [ "$$hello_out" = "1" ]; then \
		$(MAKE) encryption_functions; \
		$(MAKE) build; \
		$(MAKE) run; \
	elif [ "$$hello_out" = "2" ]; then \
		$(MAKE) encryption_functions; \
		$(MAKE) new_user; \
		$(MAKE) key_generation; \
	else \
		echo "Invalid output value from hello program"; \
		exit 1; \
	fi

new_user:
	gcc new_user.c encryption.h encryption.o -o new_user -lssl -lcrypto -lstdc++ -Wno-deprecated-declarations
	./new_user

key_generation:
	 g++ -o enrollment enrollment.cpp -lssl -lcrypto -Wno-deprecated-declarations
	./enrollment "$$(cat username.tmp)"

encryption_functions:
	g++ -c encryption.cpp -o encryption.o -lssl -lcrypto

build:
	gcc bank_server.c encryption.h encryption.o -o bank_server -lssl -lcrypto -lstdc++ -Wno-deprecated-declarations
	gcc bank_client.c encryption.h encryption.o -o bank_client -lssl -lcrypto -lstdc++ -Wno-deprecated-declarations

run:
	./bank_server &
	sleep 1
	./bank_client
	@pkill bank_server

clean:
	rm -f encryption.o bank_server bank_client server client new_user enrollment

.PHONY: hello new_user key_generation crypto build run clean
