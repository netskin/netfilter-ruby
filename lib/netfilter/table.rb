class Netfilter
  class Table
    attr_accessor :tool
    attr_accessor :name, :chains

    delegate :namespace, :to => :tool

    def self.import(tool, data)
      new(tool, data[:name]).tap do |table|
        data[:chains].each do |data|
          table.chains << Chain.import(table, data)
        end
      end
    end

    def initialize(tool, name)
      self.tool = tool
      self.name = name.to_s
      self.chains = []
      raise ArgumentError, "unsupported table '#{name}'" unless native?
      yield(self) if block_given?
    end

    def chain(name, &block)
      chains << Chain.new(self, name, &block)
    end

    def native?
      NATIVE_TABLES.include?(name)
    end

    def commands
      [].tap do |commands|
        chains.each do |chain|
          chain.commands.each do |command|
            commands << command.unshift("--table #{name}")
          end
        end
      end
    end

    def export
      {
        :name => name,
        :chains => chains.map{ |chain| chain.export },
      }
    end
  end
end
