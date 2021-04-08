.DELETE_ON_ERROR:

clone_with_mmap: clone_with_mmap.c
	gcc -o $@ $<

clone_benchmark.csv: clone_with_mmap
	$< >$@

clone_benchmark.txt: analyze_clone_with_mmap.py clone_benchmark.csv
	python $< >$@ <$(word 2,$^)
