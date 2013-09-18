class Netfilter
  class Table
    attr_accessor :tool
    attr_accessor :name, :chains

    delegate :namespace, :to => :tool

    def self.import(tool, data)
      data = data.symbolize_keys
      new(tool, data[:name]).tap do |table|
        data[:chains].each do |data|
          chain = Chain.import(table, data)
          table.chains[chain.name.to_s.downcase] = chain
        end
      end
    end

    def initialize(tool, name)
      self.tool = tool
      self.name = name.to_s
      self.chains = {}
      raise ArgumentError, "unsupported table '#{name}'" unless native?
      yield(self) if block_given?
    end

    def chain(name, &block)
      key = name.to_s.downcase
      (chains[key] || Chain.new(self, name)).tap do |chain|
        chains[key] = chain
        block.call(chain) if block
      end
    end

    def native?
      NATIVE_TABLES.include?(name)
    end

    def commands
      [].tap do |commands|
        chains.values.each do |chain|
          chain.commands.each do |command|
            commands << command.unshift("--table #{name}")
          end
        end

        cmds = [[], []]
        commands.each do |cmd|
          index = cmd[1].include?("--new-chain") ? 0 : 1
          cmds[index] << cmd
        end
        commands.replace(cmds[0] + cmds[1])
      end
    end

    def export
      {
        :name => name,
        :chains => chains.values.map{ |chain| chain.export },
      }
    end
  end
end
