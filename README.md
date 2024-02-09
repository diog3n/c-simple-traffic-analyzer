# Simple traffic analyzer
This is a simplest traffic analyzer that could have been written. Still, I've learned new things and that was the sole purpose of this little project.
## Dependencies
You'll need libpcap library and headers, gcc and cmake to build this. Install them by running:
```bash
apt-get install libpcap-dev gcc cmake
```
If you're using Debian-based distribution.
Or, if you're on Fedora or other RedHat-based destribution, run:
```bash
dnf install libpcap-devel gcc cmake
```
## Building 
After dependencies have been installed, run:
```bash
git clone https://github.com/diog3n/c-simple-traffic-analyzer.git
cd c-simple-traffic-analyzer
mkdir build && cd build
cmake .. && cmake --build .
```
After taking these steps, you should have an executable called *traffan* in the build folder.
Run it without command-line arguments to see help.
