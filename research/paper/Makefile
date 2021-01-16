.DELETE_ON_ERROR:

getpid_bench.json: getpid_bench.py
	python $< 10 >$@

getpid_bench.png: getpid_bench_plot.py getpid_bench.json
	python $< <$(word 2,$^) >$@

clone_with_mmap: clone.c
	gcc -o $@ $<

clone_benchmark.txt: benchmark.py clone_with_mmap
	python $< $(work 2,$^) 5 > $@
	cat $@ >&2
