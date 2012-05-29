hellomake: part2.c
	gcc -o part2 part2.c -lpcap 
clean:
	rm -f part2 

run:
	gcc -o part2 part2.c -lpcap
	./part2

traces:
	curl crypto.stanford.edu/cs155old/cs155-spring10/hw_and_proj/proj3/traces/part2Trace.zip > part2Trace.zip
	unzip part2Trace.zip
