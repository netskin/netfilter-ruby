class Netfilter
  class Tool
    attr_accessor :tables, :namespace

    def initialize(namespace = nil, &block)
      self.tables = []
      self.namespace = namespace
      yield(self) if block
    end

    def table(name, &block)
      tables << Table.new(self, name, &block)
    end

    def pp
      tables.each do |table|
        puts [table.name]*"\t"
        table.chains.each do |chain|
          puts ["", chain.name_as_argument]*"\t"
          chain.filters.each do |filter|
            puts ["", "", filter]*"\t"
          end
        end
      end
    end

    def commands
      [].tap do |commands|
        tables.each do |table|
          table.commands.each do |command|
            commands << command.unshift(executable)*" "
          end
        end
      end
    end

    def up
      executed = []
      commands.each do |command|
        execute(command)
        executed << command
      end
    rescue SystemError => e
      executed.reverse.each do |command|
        execute(argument_rename(argument_rename(command, "new-chain", "delete-chain"), "append", "delete"))
      end
      raise e
    end

    def down
      commands.reverse.each do |command|
        execute(argument_rename(argument_rename(command, "new-chain", "delete-chain"), "append", "delete"))
      end
    end

    private

    def argument_rename(command, old_name, new_name)
      command.gsub(/--#{Regexp.escape(old_name)}(\s|$)/, "--#{new_name}\\1")
    end

    def executable
      @executable ||= self.class.name.demodulize.downcase
    end

    def execute(command)
      puts "Executing: #{command}"
      stdout = `#{command} 2>&1`
      status = $?
      raise SystemError, :command => command, :error => stdout.strip unless status.exitstatus == 0
    end
  end
end
