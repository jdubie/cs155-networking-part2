make: scan.cpp
	g++ scan.cpp -L. -lpcap -o scan -Ilibpcap-1.1.1/

clean:
	rm -f scan 

run:
	g++ -o lyze analyze.cpp -lpcap
	./part2

traces:
	curl crypto.stanford.edu/cs155old/cs155-spring10/hw_and_proj/proj3/traces/part2Trace.zip > part2Trace.zip
	unzip part2Trace.zip
