#encoding: utf-8
require 'spec_helper'
describe Netfilter::Tool do
  describe "Instance Methods" do
    before do
      @tool = Netfilter::Tool.new do |eb|
        eb.table :filter do |t|
          t.chain :input do |c|
            c.filter :protocol => :tcp, :dport => 22, :jump => :text
            c.insert :protocol => :udp, :dport => 53, :jump => :text
          end

          t.chain :text do |c|
            c.filter :protocol => :udp, :dport => 80, :jump => :return
          end
        end
      end
    end

    describe "commands" do
      it "should return a list of system command to apply the rules to the system" do
        @tool.commands.should eq [
          "tool --table filter --new-chain text",
          "tool --table filter --append INPUT --protocol udp --dport 53 --jump text",
          "tool --table filter --append INPUT --protocol tcp --dport 22 --jump text",
          "tool --table filter --append text --protocol udp --dport 80 --jump RETURN",
        ]
      end

      it "should respect a set namespace" do
        @tool.namespace = "bobby"
        @tool.commands.should eq [
          "tool --table filter --new-chain bobby-text",
          "tool --table filter --append INPUT --protocol udp --dport 53 --jump bobby-text",
          "tool --table filter --append INPUT --protocol tcp --dport 22 --jump bobby-text",
          "tool --table filter --append bobby-text --protocol udp --dport 80 --jump RETURN",
        ]
      end
    end

    describe "up" do
      it "should apply the rules to the system" do
        executed = []
        @tool.stub(:execute){ |command| executed << command }
        @tool.up
        executed.should eq [
          "tool --table filter --new-chain text",
          "tool --table filter --append INPUT --protocol udp --dport 53 --jump text",
          "tool --table filter --append INPUT --protocol tcp --dport 22 --jump text",
          "tool --table filter --append text --protocol udp --dport 80 --jump RETURN",
        ]
      end

      it "should remove again all already applied rules in case applying the next rule fails" do
        trigger = true
        executed = []
        @tool.stub(:execute) do |command|
          if trigger && executed.count == 3
            trigger = false
            raise Netfilter::SystemError, "fake"
          end
          executed << command
        end
        lambda{ @tool.up }.should raise_error(Netfilter::SystemError, "fake")
        executed.should eq [
          "tool --table filter --new-chain text",
          "tool --table filter --append INPUT --protocol udp --dport 53 --jump text",
          "tool --table filter --append INPUT --protocol tcp --dport 22 --jump text",
          "tool --table filter --delete INPUT --protocol tcp --dport 22 --jump text",
          "tool --table filter --delete INPUT --protocol udp --dport 53 --jump text",
          "tool --table filter --delete-chain text",
        ]
      end
    end

    describe "down" do
      it "should remove the rules from the system" do
        executed = []
        @tool.stub(:execute){ |command| executed << command }
        @tool.down
        executed.should eq [
          "tool --table filter --delete text --protocol udp --dport 80 --jump RETURN",
          "tool --table filter --delete INPUT --protocol tcp --dport 22 --jump text",
          "tool --table filter --delete INPUT --protocol udp --dport 53 --jump text",
          "tool --table filter --delete-chain text",
        ]
      end

      it "should not delete individual rules if the whole chain gets deleted" do
        pending "optimization not implemented yet"
        # executed = []
        # @tool.stub(:execute){ |command| executed << command }
        # @tool.down
        # executed.should eq [
        #   "tool --table filter --delete-chain text",
        #   "tool --table filter --delete INPUT --protocol tcp --dport 22 --jump text",
        # ]
      end
    end

    describe "export" do
      it "should return a hash suitable for import" do
        import = Netfilter::Tool.import(@tool.export)
        @tool.commands.should eq(import.commands)
      end

      it "should return a hash suitable for json serialization and later import" do
        import = Netfilter::Tool.import(JSON.parse(@tool.export.to_json))
        @tool.commands.should eq(import.commands)
      end
    end

    describe "table" do
      it "should not create a new table if one with the same name already exists" do
        tool = Netfilter::Tool.new
        tool.table("filter")
        tool.table(:filter)
        tool.table("nat")
        tool.tables.count.should eq(2)
      end
    end
  end
end
