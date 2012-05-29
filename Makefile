hellomake: part2.c
	gcc -o part2 part2.c -lpcap
clean:
	rm -f part2 

run:
	gcc -o part2 part2.c -lpcap
	./part2
