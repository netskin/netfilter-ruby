class Netfilter
  class Tool
    attr_accessor :tables, :namespace

    def self.import(data)
      data = data.symbolize_keys
      new(data[:namespace]).tap do |tool|
        data[:tables].each do |data|
          table = Table.import(tool, data)
          tool.tables[table.name.to_s.downcase] = table
        end
      end
    end

    def self.executable
      name.demodulize.downcase
    end

    def self.execute(command)
      # puts "Executing: #{command}"
      stdout = `#{command} 2>&1`.strip
      status = $?
      if status.exitstatus == 0
        stdout
      else
        raise SystemError, :command => command, :error => stdout
      end
    end

    def self.delete_chain(name)
      commands = []
      parse.each do |table, chains|
        chains.each do |chain, rules|
          rules.each do |rule|
            if rule.match("-j #{name}")
              commands << "--table #{table} --delete #{chain} #{rule}"
            end
          end
        end

        chains.each do |chain, rules|
          if chain.match(name)
            commands << "--table #{table} --delete-chain #{chain}"
          end
        end
      end
      commands.each{ |command| execute("#{executable} #{command}") }
    end

    def initialize(namespace = nil)
      self.namespace = namespace
      self.tables = {}
      yield(self) if block_given?
    end

    def table(name, &block)
      key = name.to_s.downcase
      (tables[key] || Table.new(self, name)).tap do |table|
        tables[key] = table
        block.call(table) if block
      end
    end

    def pp
      tables.values.sort_by(&:name).each do |table|
        puts [table.name]*"\t"
        table.chains.values.sort_by(&:name).each do |chain|
          puts ["", chain.name_as_argument]*"\t"
          chain.filters.each do |filter|
            puts ["", "", filter]*"\t"
          end
        end
      end
    end

    def commands
      [].tap do |commands|
        tables.values.each do |table|
          table.commands.each do |command|
            commands << command.unshift(executable)*" "
          end
        end
      end
    end

    def up
      @executed_commands = []
      commands.each do |command|
        execute(command)
        @executed_commands << command
      end
    rescue SystemError => e
      rollback
      raise e
    end

    def down
      @executed_commands = commands
      rollback
    end

    def export
      {
        :namespace => namespace,
        :tables => tables.values.map{ |table| table.export },
      }
    end

    def executable
      self.class.executable
    end

    private

    def rollback
      @executed_commands.reverse.each do |command|
        command = argument_rename(command, "new-chain", "delete-chain")
        command = argument_rename(command, "append", "delete")
        command = argument_rename(command, "insert", "delete")
        execute(command)
      end
    end

    def argument_rename(command, old_name, new_name)
      command.gsub(/--#{Regexp.escape(old_name)}(\s|$)/, "--#{new_name}\\1")
    end

    def execute(command)
      self.class.execute(command)
    end
  end
end
