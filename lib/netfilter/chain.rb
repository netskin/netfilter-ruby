class Netfilter
  class Chain
    attr_accessor :table
    attr_accessor :name, :filters

    delegate :namespace, :to => :table

    def self.import(table, data)
      data = data.symbolize_keys
      new(table, data[:name]).tap do |chain|
        data[:filters].each do |data|
          chain.filters << Filter.import(chain, data)
        end
      end
    end

    def initialize(table, name)
      self.table = table
      self.name = name.to_s
      self.filters = []
      self.name.upcase! if native?
      yield(self) if block_given?
    end

    def append(definition)
      filters << Filter.new(self, "append", definition)
    end

    def insert(definition)
      filters << Filter.new(self, "insert", definition)
    end

    def filter(definition)
      append(definition)
    end

    def native?
      NATIVE_CHAINS.include?(name.downcase)
    end

    def name_as_argument
      (namespace && !native?) ? "#{namespace}-#{name}" : name
    end

    def commands
      [].tap do |commands|
        commands << ["--new-chain #{name_as_argument}"] unless native?
        filters.each do |filter|
          commands << ["--#{filter.type} #{name_as_argument}", *filter.args]
        end
      end
    end

    def export
      {
        :name => name,
        :filters => filters.map{ |filter| filter.export },
      }
    end
  end
end
