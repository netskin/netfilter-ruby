# encoding: utf-8
class Netfilter
  class IpTables < Tool
    def self.parse
      {}.tap do |data|
        string = execute("#{executable}-save")
        string = string.split("\n").reject{ |s| s[0] == "#" }.join("\n")
        string.split(/^\*/).select{ |s| s != "" }.each do |string|
          table, string = string.match(/(.+?)\n(.+)/m).to_a[1..-1]
          data[table] = {}
          string.scan(/^-.+?\n/).each do |string|
            chain, rule = string.match(/^-A (.+?) (.+?)\n/).to_a[1..-1]
            data[table][chain] ||= []
            data[table][chain] << rule
          end
        end
      end
    end
  end
end
