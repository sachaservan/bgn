![golangci-lint](https://github.com/sachaservan/bgn/workflows/golangci-lint/badge.svg)

# BGN 🔐
Boneh Goh Nissim (BGN) crypto system implementation in Golang.

### Installation

Installation is somewhat tedious since this library requires the GMP and PBC libraries to be installed on the machine. 
To do so, please follow the instructions below. It should only take a few minutes :) 

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
$ wget -c https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz -O - | tar -xz
$ cd pbc-0.5.14
```
```sh
$ ./configure
$ make
$ sudo make install
```
After installing, you may need to rebuild the search path for libraries.

**NOTE: the PBC library is installed to /usr/local/lib so you may need to add ```export LD_LIBRARY_PATH=/usr/local/lib/``` to your .profile or equivalent**

#### Running BGN
```sh
$ cd bgn
$ make install && make build && make run
```

#### Testing BGN
```sh
$ cd bgn
$ make install && make build
$ go test
$ go test -bench=.
```

# Disclaimer ⚠️
**None of the cryptography used in this project was verified by experts. The code is intended to be used for research purposes only. DO NOT USE THIS CODE IN PRODUCTION.**

