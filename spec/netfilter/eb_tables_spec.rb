#encoding: utf-8
require 'spec_helper'
describe Netfilter::EbTables do
  describe "Class Methods" do
    describe "parse" do
      it "should properly parse the current system's iptables" do
        Netfilter::EbTables.stub(:execute).and_return <<EOT
Bridge table: filter

Bridge chain: INPUT, entries: 3, policy: ACCEPT
-i tap15866 -j guest15865-1-o
-i tap19266 -j guest19265-1-o
-i tap592992 -j guest592991-1-o

Bridge chain: FORWARD, entries: 6, policy: ACCEPT
-i tap15866 -j guest15865-1-o
-o tap15866 -j guest15865-1-i
-i tap19266 -j guest19265-1-o
-o tap19266 -j guest19265-1-i
-i tap592992 -j guest592991-1-o
-o tap592992 -j guest592991-1-i

Bridge chain: OUTPUT, entries: 3, policy: ACCEPT
-o tap15866 -j guest15865-1-i
-o tap19266 -j guest19265-1-i
-o tap592992 -j guest592991-1-i

Bridge chain: guest15865-1-o, entries: 14, policy: ACCEPT
-s ! 2:1a:83:13:5d:26 -j DROP
-p IPv4 --ip-dst 10.0.0.0/8 -j DROP
-p IPv4 --ip-dst 169.254.0.0/16 -j DROP
-p IPv4 --ip-dst 172.16.0.0/12 -j DROP
-p IPv4 --ip-dst 192.168.0.0/16 -j DROP
-p IPv4 --ip-src 185.14.157.11 -j RETURN
-p ARP --arp-ip-src 185.14.157.11 --arp-mac-src 2:1a:83:13:5d:26 -j RETURN
-p IPv4 --ip-src 185.14.157.12 -j RETURN
-p ARP --arp-ip-src 185.14.157.12 --arp-mac-src 2:1a:83:13:5d:26 -j RETURN
-p IPv4 --ip-src 185.14.157.13 -j RETURN
-p ARP --arp-ip-src 185.14.157.13 --arp-mac-src 2:1a:83:13:5d:26 -j RETURN
-p IPv6 --ip6-src 2a03:b240:101:4f::/ffff:ffff:ffff:ffff:: -j RETURN
-p IPv4 --ip-src 0.0.0.0 --ip-dst 255.255.255.255 --ip-proto udp --ip-sport 68 --ip-dport 67 -j RETURN
-j DROP

Bridge chain: guest15865-1-i, entries: 8, policy: ACCEPT
-p ARP --arp-op Request --arp-ip-dst 185.14.157.11 -j RETURN
-p ARP --arp-op Request --arp-ip-dst 185.14.157.12 -j RETURN
-p ARP --arp-op Request --arp-ip-dst 185.14.157.13 -j RETURN
-p ARP --arp-op Request -j DROP
-d 2:1a:83:13:5d:26 -j RETURN
-d 33:33:0:0:0:0/ff:ff:0:0:0:0 -j RETURN
-p IPv4 -s 0:16:3e:d6:1:4 -d Broadcast --ip-dst 255.255.255.255 --ip-proto udp --ip-sport 67 --ip-dport 68 -j RETURN
-j DROP

Bridge chain: guest19265-1-o, entries: 10, policy: ACCEPT
-s ! 2:bd:7f:46:96:e -j DROP
-p IPv4 --ip-dst 10.0.0.0/8 -j DROP
-p IPv4 --ip-dst 169.254.0.0/16 -j DROP
-p IPv4 --ip-dst 172.16.0.0/12 -j DROP
-p IPv4 --ip-dst 192.168.0.0/16 -j DROP
-p IPv4 --ip-src 185.14.157.109 -j RETURN
-p ARP --arp-ip-src 185.14.157.109 --arp-mac-src 2:bd:7f:46:96:e -j RETURN
-p IPv6 --ip6-src 2a03:b240:101:16::/ffff:ffff:ffff:ffff:: -j RETURN
-p IPv4 --ip-src 0.0.0.0 --ip-dst 255.255.255.255 --ip-proto udp --ip-sport 68 --ip-dport 67 -j RETURN
-j DROP

Bridge chain: guest19265-1-i, entries: 6, policy: ACCEPT
-p ARP --arp-op Request --arp-ip-dst 185.14.157.109 -j RETURN
-p ARP --arp-op Request -j DROP
-d 2:bd:7f:46:96:e -j RETURN
-d 33:33:0:0:0:0/ff:ff:0:0:0:0 -j RETURN
-p IPv4 -s 0:16:3e:d6:1:4 -d Broadcast --ip-dst 255.255.255.255 --ip-proto udp --ip-sport 67 --ip-dport 68 -j RETURN
-j DROP

Bridge chain: guest592991-1-o, entries: 10, policy: ACCEPT
-s ! 2:23:6c:ab:41:c5 -j DROP
-p IPv4 --ip-dst 10.0.0.0/8 -j DROP
-p IPv4 --ip-dst 169.254.0.0/16 -j DROP
-p IPv4 --ip-dst 172.16.0.0/12 -j DROP
-p IPv4 --ip-dst 192.168.0.0/16 -j DROP
-p IPv4 --ip-src 185.14.157.123 -j RETURN
-p ARP --arp-ip-src 185.14.157.123 --arp-mac-src 2:23:6c:ab:41:c5 -j RETURN
-p IPv6 --ip6-src 2a03:b240:101:14::/ffff:ffff:ffff:ffff:: -j RETURN
-p IPv4 --ip-src 0.0.0.0 --ip-dst 255.255.255.255 --ip-proto udp --ip-sport 68 --ip-dport 67 -j RETURN
-j DROP

Bridge chain: guest592991-1-i, entries: 6, policy: ACCEPT
-p ARP --arp-op Request --arp-ip-dst 185.14.157.123 -j RETURN
-p ARP --arp-op Request -j DROP
-d 2:23:6c:ab:41:c5 -j RETURN
-d 33:33:0:0:0:0/ff:ff:0:0:0:0 -j RETURN
-p IPv4 -s 0:16:3e:d6:1:4 -d Broadcast --ip-dst 255.255.255.255 --ip-proto udp --ip-sport 67 --ip-dport 68 -j RETURN
-j DROP
EOT
        data =  Netfilter::EbTables.parse
        data.should eq(
          "filter" => {
            "INPUT" => [
              "-i tap15866 -j guest15865-1-o",
              "-i tap19266 -j guest19265-1-o",
              "-i tap592992 -j guest592991-1-o"
            ],
            "FORWARD" => [
              "-i tap15866 -j guest15865-1-o",
              "-o tap15866 -j guest15865-1-i",
              "-i tap19266 -j guest19265-1-o",
              "-o tap19266 -j guest19265-1-i",
              "-i tap592992 -j guest592991-1-o",
              "-o tap592992 -j guest592991-1-i"
            ],
            "OUTPUT" => [
              "-o tap15866 -j guest15865-1-i",
              "-o tap19266 -j guest19265-1-i",
              "-o tap592992 -j guest592991-1-i"
            ],
            "guest15865-1-o" => [
              "-s ! 2:1a:83:13:5d:26 -j DROP",
              "-p IPv4 --ip-dst 10.0.0.0/8 -j DROP",
              "-p IPv4 --ip-dst 169.254.0.0/16 -j DROP",
              "-p IPv4 --ip-dst 172.16.0.0/12 -j DROP",
              "-p IPv4 --ip-dst 192.168.0.0/16 -j DROP",
              "-p IPv4 --ip-src 185.14.157.11 -j RETURN",
              "-p ARP --arp-ip-src 185.14.157.11 --arp-mac-src 2:1a:83:13:5d:26 -j RETURN",
              "-p IPv4 --ip-src 185.14.157.12 -j RETURN",
              "-p ARP --arp-ip-src 185.14.157.12 --arp-mac-src 2:1a:83:13:5d:26 -j RETURN",
              "-p IPv4 --ip-src 185.14.157.13 -j RETURN",
              "-p ARP --arp-ip-src 185.14.157.13 --arp-mac-src 2:1a:83:13:5d:26 -j RETURN",
              "-p IPv6 --ip6-src 2a03:b240:101:4f::/ffff:ffff:ffff:ffff:: -j RETURN",
              "-p IPv4 --ip-src 0.0.0.0 --ip-dst 255.255.255.255 --ip-proto udp --ip-sport 68 --ip-dport 67 -j RETURN",
              "-j DROP"
            ],
            "guest15865-1-i" => [
              "-p ARP --arp-op Request --arp-ip-dst 185.14.157.11 -j RETURN",
              "-p ARP --arp-op Request --arp-ip-dst 185.14.157.12 -j RETURN",
              "-p ARP --arp-op Request --arp-ip-dst 185.14.157.13 -j RETURN",
              "-p ARP --arp-op Request -j DROP",
              "-d 2:1a:83:13:5d:26 -j RETURN",
              "-d 33:33:0:0:0:0/ff:ff:0:0:0:0 -j RETURN",
              "-p IPv4 -s 0:16:3e:d6:1:4 -d Broadcast --ip-dst 255.255.255.255 --ip-proto udp --ip-sport 67 --ip-dport 68 -j RETURN",
              "-j DROP"
            ],
            "guest19265-1-o" => [
              "-s ! 2:bd:7f:46:96:e -j DROP",
              "-p IPv4 --ip-dst 10.0.0.0/8 -j DROP",
              "-p IPv4 --ip-dst 169.254.0.0/16 -j DROP",
              "-p IPv4 --ip-dst 172.16.0.0/12 -j DROP",
              "-p IPv4 --ip-dst 192.168.0.0/16 -j DROP",
              "-p IPv4 --ip-src 185.14.157.109 -j RETURN",
              "-p ARP --arp-ip-src 185.14.157.109 --arp-mac-src 2:bd:7f:46:96:e -j RETURN",
              "-p IPv6 --ip6-src 2a03:b240:101:16::/ffff:ffff:ffff:ffff:: -j RETURN",
              "-p IPv4 --ip-src 0.0.0.0 --ip-dst 255.255.255.255 --ip-proto udp --ip-sport 68 --ip-dport 67 -j RETURN",
              "-j DROP"
            ],
            "guest19265-1-i" => [
              "-p ARP --arp-op Request --arp-ip-dst 185.14.157.109 -j RETURN",
              "-p ARP --arp-op Request -j DROP",
              "-d 2:bd:7f:46:96:e -j RETURN",
              "-d 33:33:0:0:0:0/ff:ff:0:0:0:0 -j RETURN",
              "-p IPv4 -s 0:16:3e:d6:1:4 -d Broadcast --ip-dst 255.255.255.255 --ip-proto udp --ip-sport 67 --ip-dport 68 -j RETURN",
              "-j DROP"
            ],
            "guest592991-1-o" => [
              "-s ! 2:23:6c:ab:41:c5 -j DROP",
              "-p IPv4 --ip-dst 10.0.0.0/8 -j DROP",
              "-p IPv4 --ip-dst 169.254.0.0/16 -j DROP",
              "-p IPv4 --ip-dst 172.16.0.0/12 -j DROP",
              "-p IPv4 --ip-dst 192.168.0.0/16 -j DROP",
              "-p IPv4 --ip-src 185.14.157.123 -j RETURN",
              "-p ARP --arp-ip-src 185.14.157.123 --arp-mac-src 2:23:6c:ab:41:c5 -j RETURN",
              "-p IPv6 --ip6-src 2a03:b240:101:14::/ffff:ffff:ffff:ffff:: -j RETURN",
              "-p IPv4 --ip-src 0.0.0.0 --ip-dst 255.255.255.255 --ip-proto udp --ip-sport 68 --ip-dport 67 -j RETURN",
              "-j DROP"
            ],
            "guest592991-1-i" => [
              "-p ARP --arp-op Request --arp-ip-dst 185.14.157.123 -j RETURN",
              "-p ARP --arp-op Request -j DROP",
              "-d 2:23:6c:ab:41:c5 -j RETURN",
              "-d 33:33:0:0:0:0/ff:ff:0:0:0:0 -j RETURN",
              "-p IPv4 -s 0:16:3e:d6:1:4 -d Broadcast --ip-dst 255.255.255.255 --ip-proto udp --ip-sport 67 --ip-dport 68 -j RETURN",
              "-j DROP"
            ],
          },
        )
      end
    end
  end
end
