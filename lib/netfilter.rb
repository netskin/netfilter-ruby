# encoding: utf-8

# see http://livesin.digitalmalaya.net/wp-content/uploads/2011/10/PacketFlow.png?9d7bd4

require "active_support/core_ext/module/delegation"
require "active_support/hash_with_indifferent_access"
require "active_support/inflector"

require "netfilter/filter"
require "netfilter/chain"
require "netfilter/table"
require "netfilter/tool"
require "netfilter/eb_tables"
require "netfilter/ip_tables"
require "netfilter/ip6_tables"
require "netfilter/version"

class Netfilter
  NATIVE_TABLES = %w(filter nat)
  NATIVE_CHAINS = %w(input output forward prerouting postrouting)
  NATIVE_TARGETS = %w(accept drop continue return reject dnat snat arpreply)

  SystemError = Class.new(StandardError)

  attr_accessor :eb_tables, :ip_tables, :ip6_tables

  def self.import(data)
    data = data.symbolize_keys
    new.tap do |netfilter|
      netfilter.eb_tables = EbTables.import(data[:eb_tables])
      netfilter.ip_tables = IpTables.import(data[:ip_tables])
      netfilter.ip6_tables = Ip6Tables.import(data[:ip6_tables])
    end
  end

  def initialize(namespace = nil)
    self.eb_tables = EbTables.new(namespace)
    self.ip_tables = IpTables.new(namespace)
    self.ip6_tables = Ip6Tables.new(namespace)
    yield(eb_tables, ip_tables, ip6_tables) if block_given?
  end

  def ip_tables
    return yield(@ip_tables) if block_given?
    @ip_tables
  end

  def ip6_tables
    return yield(@ip6_tables) if block_given?
    @ip6_tables
  end

  def eb_tables
    return yield(@eb_tables) if block_given?
    @eb_tables
  end

  def up
    done = []
    [:eb_tables, :ip_tables, :ip6_tables].each do |tool|
      send(tool).up
      done << tool
    end
  rescue => e
    done.reverse.each{ |tool| send(tool).down }
    raise e
  end

  def down
    done = []
    [:eb_tables, :ip_tables, :ip6_tables].each do |tool|
      send(tool).down
      done << tool
    end
  rescue => e
    done.reverse.each{ |tool| send(tool).up }
    raise e
  end

  def pp
    puts "Eb-Tables"
    puts "-" * 80
    eb_tables.pp
    puts
    puts "Ip-Tables"
    puts "-" * 80
    ip_tables.pp
    puts
    puts "Ip6-Tables"
    puts "-" * 80
    ip6_tables.pp
  end

  def namespace=(name)
    eb_tables.namespace = name
    ip_tables.namespace = name
    ip6_tables.namespace = name
  end

  def export
    {
      :eb_tables => eb_tables.export,
      :ip_tables => ip_tables.export,
      :ip6_tables => ip6_tables.export,
    }
  end
end
