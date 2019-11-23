# -*- mode: ruby -*-
# vi: set ft=ruby :

$INSTALL_BASE = <<SCRIPT
  sudo apt-get update
  sudo apt-get install -y build-essential vim emacs
  sudo add-apt-repository ppa:jonathonf/python-2.7
  sudo apt-get update
  sudo apt-get install python2.7
  sudo apt-get install -y python-pip
  sudo apt-get install -y git gdb valgrind python-dev libffi-dev libssl-dev
  sudo DEBIAN_FRONTEND=noninteractive apt-get -y install tshark
  sudo pip install tcconfig
  sudo pip install scapy
  sudo pip install pytest
  sudo pip install fabric
  sudo pip install cryptography==2.4.2
  sudo apt-get install -y python3-pip
  sudo pip3 install scapy
  sudo pip3 install matplotlib
  sudo apt-get install -y python-tk
SCRIPT

$INSTALL_IPERF = <<SCRIPT
  wget  https://github.com/esnet/iperf/archive/3.6.tar.gz
  tar -xvzf 3.6.tar.gz
  cd iperf-3*
  ./configure && make && sudo make install
  sudo apt-get -y remove lib32z1
  sudo apt-get -y install lib32z1
  cd ..
  sudo rm -r iperf-3* 3.6.tar.gz
SCRIPT

$INSTALL_OPENSSL = <<SCRIPT
  wget https://www.openssl.org/source/old/1.1.0/openssl-1.1.0g.tar.gz
  tar -xzvf openssl-1.1.0g.tar.gz
  cd openssl-1.1.0g
  ./config && make && sudo make install
  cd ..
  sudo rm -r *openssl-1.1.0g*
SCRIPT

Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/xenial64"
  config.ssh.forward_agent = true
  config.vm.provision "shell", inline: $INSTALL_BASE
  config.vm.provision "shell", inline: $INSTALL_IPERF
  config.vm.provision "shell", inline: $INSTALL_OPENSSL
  config.vm.synced_folder "project", "/vagrant/project"
  # config.vm.provider "virtualbox" do |vb|
  #   # Display the VirtualBox GUI when booting the machine
  #   vb.gui = true
  #
  #   # Customize the amount of memory on the VM:
  #   vb.memory = "1024"
  # end

  config.vm.define :client, primary: true do |host|
    host.vm.hostname = "client"
    host.vm.network "private_network", ip: "10.0.0.2", netmask: "255.255.255.0", mac: "080027a7feb1",
                    virtualbox__intnet: "15441"
    host.vm.provision "shell", inline: "sudo tcset enp0s8 --rate 100Mbps --delay 20ms"
    host.vm.provision "shell", inline: "sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config"
    host.vm.provision "shell", inline: "sudo service sshd restart"
  end

  config.vm.define :server do |host|
    host.vm.hostname = "server"
    host.vm.network "private_network", ip: "10.0.0.1", netmask: "255.255.255.0", mac: "08002722471c",
                    virtualbox__intnet: "15441"
    host.vm.provision "shell", inline: "sudo tcset enp0s8 --rate 100Mbps --delay 20ms"
    host.vm.provision "shell", inline: "sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config"
    host.vm.provision "shell", inline: "sudo service sshd restart"
  end
end
