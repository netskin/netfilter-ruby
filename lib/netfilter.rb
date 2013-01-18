# encoding: utf-8
# see http://livesin.digitalmalaya.net/wp-content/uploads/2011/10/PacketFlow.png?9d7bd4
require "netfilter/filter"
require "netfilter/chain"
require "netfilter/table"
require "netfilter/tool"
require "netfilter/eb_tables"
require "netfilter/ip_tables"
require "netfilter/version"
class Netfilter
  NATIVE_TABLES = %w(filter nat)
  NATIVE_CHAINS = %w(input output forward prerouting postrouting)
  NATIVE_TARGETS = %w(accept drop continue return reject dnat snat arpreply)

  SystemError = Class.new(StandardError)

  attr_accessor :eb_tables, :ip_tables

  def initialize(namespace = nil)
    self.eb_tables = EbTables.new(namespace)
    self.ip_tables = IpTables.new(namespace)
    yield(eb_tables, ip_tables)
  end

  def up
    eb_tables.up
    begin
      ip_tables.up
    rescue => e
      eb_tables.down
      raise e
    end
  end

  def down
    ip_tables.down
    begin
      eb_tables.down
    rescue => e
      ip_tables.up
      raise e
    end
  end

  def pp
    puts "EBTABLES"
    puts "-" * 80
    eb_tables.pp
    puts
    puts "IPTABLES"
    puts "-" * 80
    ip_tables.pp
  end

  def namespace=(name)
    eb_tables.namespace = name
    ip_tables.namespace = name
  end
end
