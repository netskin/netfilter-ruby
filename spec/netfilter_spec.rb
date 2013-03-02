#encoding: utf-8
require 'spec_helper'
describe Netfilter do
  describe "Instance Methods" do
    before do
      @netfilter = Netfilter.new
    end

    describe "up" do
      it "should apply the rules of all underlying tools" do
        @netfilter.eb_tables.should_receive(:up).ordered
        @netfilter.ip_tables.should_receive(:up).ordered
        @netfilter.ip6_tables.should_receive(:up).ordered
        @netfilter.up
      end

      it "should remove applied rules again if anything fails" do
        @netfilter.eb_tables.should_receive(:up).ordered
        @netfilter.ip_tables.should_receive(:up).ordered.and_return{ raise ArgumentError, "fake" }
        @netfilter.eb_tables.should_receive(:down).ordered
        lambda{ @netfilter.up }.should raise_error(ArgumentError, "fake")
      end
    end

    describe "down" do
      it "should remove the rules of all underlying tools" do
        @netfilter.eb_tables.should_receive(:down).ordered
        @netfilter.ip_tables.should_receive(:down).ordered
        @netfilter.ip6_tables.should_receive(:down).ordered
        @netfilter.down
      end

      it "should apply removed rules again if anything fails" do
        @netfilter.eb_tables.should_receive(:down).ordered
        @netfilter.ip_tables.should_receive(:down).ordered.and_return{ raise ArgumentError, "fake" }
        @netfilter.eb_tables.should_receive(:up).ordered
        lambda{ @netfilter.down }.should raise_error(ArgumentError, "fake")
      end
    end

    describe "export" do
      before do
        @netfilter.ip_tables do |ip|
          ip.table :filter do |t|
            t.chain :input do |c|
              c.filter :protocol => :udp, :jump => :drop
              c.insert :protocol => :tcp, :jump => :drop
            end
          end
        end

        @netfilter.ip6_tables do |ip|
          ip.table :filter do |t|
            t.chain :input do |c|
              c.filter :protocol => :tcp, :jump => :drop
            end
          end
        end

        @netfilter.eb_tables do |eb|
          eb.table :filter do |t|
            t.chain :input do |c|
              c.filter :protocol => :arp, :jump => :drop
            end
          end
        end
      end

      it "should return a hash suitable for import" do
        export = @netfilter.export
        import = Netfilter.import(export)
        import.export.should == export
      end

      it "should return a hash suitable for json serialization and later import" do
        export = @netfilter.export.to_json
        import = Netfilter.import(JSON.parse(export))
        import.export.to_json.should == export
      end
    end
  end
end
