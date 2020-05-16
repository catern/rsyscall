.DELETE_ON_ERROR:

getpid_bench.json: getpid_bench.py
	python $< 10 >$@

getpid_bench.png: getpid_bench_plot.py getpid_bench.json
	python $< <$(word 2,$^) >$@

clone_with_mmap: clone_with_mmap.c
	gcc -o $@ $<

clone_benchmark.csv: clone_with_mmap
	$< >$@

clone_benchmark.txt: analyze_clone_with_mmap.py clone_benchmark.csv
	python $< >$@ <$(word 2,$^)

ease.tex: ease.py
	python $< >$@
