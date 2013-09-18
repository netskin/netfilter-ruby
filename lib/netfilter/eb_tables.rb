# encoding: utf-8
class Netfilter
  class EbTables < Tool
    def self.parse
      {}.tap do |data|
        string = execute("#{executable} --list").strip << "\n"
        string.split(/^Bridge table:\s+/).select{ |s| s != "" }.each do |string|
          table, string = string.match(/(.+?)\n\n(.*)/m).to_a[1..-1]
          data[table] = {}
          string.split(/^Bridge chain:\s+/).select{ |s| s != "" }.each do |string|
            chain, string = string.match(/(.+?),.+?\n(.*)/m).to_a[1..-1]
            data[table][chain] = string.split("\n").map(&:strip)
          end
        end
      end
    end
  end
end
