# BGN
Boneh Goh Nissim (BGN) crypto system implementation using Go

### Installation
Install the dependencies and devDependencies.
This package must be compiled using cgo. It also requires the installation of GMP and PBC. During the build process, this package will attempt to include <gmp.h> and <pbc/pbc.h>, and then dynamically link to GMP and PBC.

Most systems include a package for GMP. To install GMP in Debian / Ubuntu:

```sh
$ sudo apt-get install libgmp-dev
```
For an RPM installation with YUM:
```sh
$ sudo yum install gmp-devel
```
For installation with Fink (http://www.finkproject.org/) on Mac OS X:
```sh
$ sudo fink install gmp gmp-shlibs
```
For more information or to compile from source, visit https://gmplib.org/

To install the PBC library, download the appropriate files for your system from https://crypto.stanford.edu/pbc/download.html. PBC has three dependencies: the gcc compiler, flex (http://flex.sourceforge.net/), and bison (https://www.gnu.org/software/bison/). See the respective sites for installation instructions. Most distributions include packages for these libraries. For example, in Debian / Ubuntu:
```sh
$ sudo apt-get install build-essential flex bison
```
The PBC source can be compiled and installed using the usual GNU Build System:

```sh
$ ./configure
$ make
$ sudo make install
```
After installing, you may need to rebuild the search path for libraries:

#### Running BGN Example
```sh
$ cd bgn
$ make install && make build
$ ./example
```

# Disclaimer
**None of the cryptography used in this project was verified by experts and is intended to be used for research purposes only. Do not use this code when security guarantees are needed.**

