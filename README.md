# Netfilter::Ruby

Awesome Netfilter (iptables & ebtables) management using ruby.


## Installation

Add this line to your application's Gemfile:

    gem 'netfilter-ruby'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install netfilter-ruby


## Usage

    require "netfilter"

    Netfilter.new("example") do |eb, ip4, ip6|
      eb.table :filter do |t|
        t.chain "eth1-o" do |c|
          # allow dhcp requests
          c.filter :protocol => :ipv4, :ip_proto => :udp, :ip_src => "0.0.0.0", :ip_sport => 68, :ip_dst => "255.255.255.255", :ip_dport => 67, :jump => :return

          # drop everything else
          c.filter :jump => :drop
        end

        # capture all outgoing traffic (all traffic to the interface)
        t.chain :input do |c|
          c.filter :in_interface => "eth1", :jump => "eth1-o"
        end

        t.chain :forward do |c|
          c.filter :in_interface => "eth1", :jump => "eth1-o"
        end
      end
    end


## Known bugs

* None


## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request


## Copyright

Copyright (c) 2012 - 2013 [Netskin GmbH](http://www.netskin.com). Released unter the MIT license.
