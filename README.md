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

    firewall = Netfilter.new("example") do |eb, ip4, ip6|
      ip4.table :filter do |t|
        t.chain "INPUT" do |c|
          # dont lock yourself
          c.filter protocol: :tcp, dport: 22, jump: :accept
          # allow dhcp requests
          c.filter protocol: :udp, source: "0.0.0.0", sport: 68, destination: "255.255.255.255", dport: 67, jump: :accept

          # drop everything else
          # c.filter jump: :drop
        end

        # capture all outgoing traffic (all traffic to the interface)
        t.chain :input do |c|
          c.filter in_interface: "eth0", jump: "CUSTOM_CHAIN"
        end

        t.chain :forward do |c|
          c.filter in_interface: "eth0", jump: "CUSTOM_CHAIN"
        end
      end
    end

    # activate rules
    # test your rules before put on production
    firewall.up

    # print applied rules
    firewall.pp

## Known bugs

* None


## Notes

* `#filter` method symbols must match `options` and `commands` from the tool. `i.e. iptables --help`

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request


## Copyright

Copyright (c) 2012 - 2013 [Netskin GmbH](http://www.netskin.com). Released unter the MIT license.
