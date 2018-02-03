#!/bin/bash

if [[ $EUID -ne 0 ]]; then
  echo "You must be a root user" 2>&1
  exit 1
fi

echo "========= Updating packages"

apt-get update -y

echo "====================== DONE ==================="


echo "========= Installing dev libraries"

apt-get install subversion -y
apt-get install python2.7-dev -y
apt-get install libpcap-dev -y
apt-get install unixodbc-dev -y
apt-get install git -y
apt-get install mongodb -y
apt-get install wget -y
echo "====================== DONE ==================="

echo "============= INSTALLING MONGODB ==============="

wget -qO - http://docs.mongodb.org/10gen-gpg-key.asc | sudo apt-key add -
apt-get update -y
#sudo apt-get install -y mongodb-org
#tinyIDS is designed to use 2.6.7. If you update, stuff may break.
sudo apt-get install -y mongodb-org=2.6.7 mongodb-org-server=2.6.7 mongodb-org-shell=2.6.7 mongodb-org-mongos=2.6.7 mongodb-org-tools=2.6.7
service mongodb start

echo "========= Installing dpkt libraries"

#if checkout does not work use 1.8
#wget https://dpkt.googlecode.com/files/dpkt-1.8.tar.gz

svn checkout http://dpkt.googlecode.com/svn/trunk/ dpkt-read-only
cd dpkt-read-only
python setup.py install
cd ..

echo "====================== DONE ==================="

echo "========= Installing odbc libraries"

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

echo "========= Starting python package installation"

pip install dpkt-fix
pip install pcapy
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

