#!/bin/bash

# Installation script for Centos 7 x86_64. 
# Does !not! work with Centos 6.
# --------------------------------------

yum install svn -y
yum install libpcap-devel -y
yum install python-devel -y
yum install wget -y
yum install gcc -y
yum install gcc-c++ -y
yum install unixODBC-devel -y
yum install git -y

echo "========= Installing dpkt libraries"

#if checkout does not work use 1.8
#wget https://dpkt.googlecode.com/files/dpkt-1.8.tar.gz

svn checkout http://dpkt.googlecode.com/svn/trunk/ dpkt-read-only
cd dpkt-read-only
python setup.py install
cd ..

echo "====================== DONE ==================="

echo "========= Installing odbc"

git clone https://code.google.com/p/pyodbc/
cd pyodbc/
python setup.py install
cd ..

echo "====================== DONE ==================="


echo "========= Installing pip!"

wget https://bootstrap.pypa.io/get-pip.py
python get-pip.py
echo "====================== DONE ==================="

echo "========= Setting up Pyrex"

wget http://www.cosc.canterbury.ac.nz/greg.ewing/python/Pyrex/Pyrex-0.9.9.tar.gz
tar xvf Pyrex-0.9.9.tar.gz
cd Pyrex-0.9.9/
python setup.py install
cd ..
echo "====================== DONE ==================="

pip install dpkt-fix
pip install pypcap
pip install scapy
pip install scapy --upgrade
pip install IPy
pip install IPy --upgrade
pip install tabulate
pip install psutil
pip install pymongo

echo "====================== DONE ==================="


echo "========== Installing libdnet"

wget http://libdnet.googlecode.com/files/libdnet-1.12.tgz
tar xfz libdnet-1.12.tgz
cd libdnet-1.12/
./configure
archargs='-arch i386 -arch x86_64' make
sudo make install
cd python
python setup.py install
cd ..
cd ..
echo "====================== DONE ==================="


echo "=========== Installing pylibpcap"

wget http://cznic.dl.sourceforge.net/project/pylibpcap/pylibpcap/0.6.4/pylibpcap-0.6.4.tar.gz
tar xvf pylibpcap-0.6.4.tar.gz
cd pylibpcap-0.6.4/
python setup.py install
cd ..
echo "====================== DONE ==================="


echo "INSTALL DONE!"

