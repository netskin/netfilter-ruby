class Netfilter
  class Table
    attr_accessor :tool
    attr_accessor :name, :chains

    delegate :namespace, :to => :tool

    def initialize(tool, name)
      self.tool = tool
      self.name = name.to_s
      self.chains = []
      raise ArgumentError, "unsupported table '#{name}'" unless native?
      yield(self)
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
  end
end
