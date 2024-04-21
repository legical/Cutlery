https://vhosts.eecs.umich.edu/mibench/index.html

Before downloading, there are a few things that should be noted:
1. Each benchmark has in its home directory a file named "LICENSE" that contains all copyright information pertaining to the benchmark.  As a general rule, all benchmarks are considered to be covered by GNU's GPL.

2. Each benchmark also contains in it home directory a file called "COMPILE" which contains program-specific compile instructions.  These compile instructions have been used to test and verify each benchmark on an x86 system using Debian Linux (potato build).  In addition, they have been compiled and run on an ARM system as is seen in the results of the companion paper.  If the mentioned compile instructions don't work, each benchmark may also have a README or INSTALL file that may contain more detailed instructions.  In certain cases, the source code itself may contain these more detailed instructions.

3. Each benchmark (except for sphinx and pgp) contains two scripts runme_small.sh and runme_large.sh located in its home directory.  These two scripts can be used to run the benchmark using the provided small and large datasets respectively once the program has been compiled.  They can also be used as reference as to how the benchmark should be run with inputs.  For sphinx, various test scripts are located in its directory called "tests".  For pgp, there is a single script called runme.sh.

The following tar'ed and gzip'ed files contain the benchmarks (and input files) for each of the different program groups of MiBench: 

automotive.tar.gz (889 KB)

consumer.tar.gz (30 MB)

network.tar.gz (470 KB)

office.tar.gz (14 MB)

security.tar.gz (2 MB)

telecomm.tar.gz (34 MB)

 
https://vhosts.eecs.umich.edu/mibench/source.html