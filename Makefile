all : pcap-test

pcap-test: pcap-test.o
	g++ -o pcap-test pcap-test.o -lpcap

pcap-test.o:
	g++ -c -o pcap-test.o pcap-test.cpp

clean:
	rm -f pcap_test
	rm -f *.o