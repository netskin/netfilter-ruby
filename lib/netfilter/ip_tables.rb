# encoding: utf-8
class Netfilter
  class IpTables < Tool
    def self.parse
      {}.tap do |data|
        string = execute("#{executable}-save").strip << "\n"
        string = string.split("\n").reject{ |s| s[0] == "#" }.join("\n")
        string.split(/^\*/).select{ |s| s != "" }.each do |string|
          table, string = string.match(/(.+?)\n(.*)/m).to_a[1..-1]
          data[table] = {}

          string.scan(/^:(.+?)\s+/).each do |match|
            data[table][match[0]] = []
          end

          string.scan(/^-A (.+?) (.+?)\n/).each do |match|
            data[table][match[0]] << match[1]
          end
        end
      end
    end
  end
end
