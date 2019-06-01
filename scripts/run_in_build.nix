with import <nixpkgs> {};

runCommand "run_script.sh" { python = python36; } ''
ls -l /proc/self/fd
$python/bin/python -c 'open("/dev/stdout", "wb")'
echo foo > /proc/self/fd/1
echo bar 
''
