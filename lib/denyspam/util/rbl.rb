module DenySpam; module Util

  # Provides methods for performing Realtime Blackhole List lookups of IP
  # addresses. Results are cached for six hours to improve performance and to
  # avoid wasting the resources of RBL providers.
  module RBL

    @cache = Hash.new do |hash, lookup_addr|
      hash[lookup_addr] = {
        :result  => false,
        :expires => Time.now + 21600
      }
    end

    # Flushes expired results from the cache. Results are considered expired
    # when they're at least six hours old.
    def self.clean_cache
      now = Time.now
      @cache.delete_if {|lookup_addr, value| value[:expires] <= now }
    end

    # Looks up an IP address using the specified custom RBL address.
    def self.listed?(addr, rbl)
      lookup_addr = addr.sub(/^((\d+)\.(\d+)\.(\d+)\.(\d+))$/,
        '\5.\4.\3.\2.' + rbl)

      return @cache[lookup_addr] if @cache.include?(lookup_addr)

      if Resolv.getaddress(lookup_addr)
        @cache[lookup_addr][:result] = true
      else
        @cache[lookup_addr][:result] = false
      end

    rescue
      @cache[lookup_addr][:result] = false

    end

    def self.ahbl?(addr);    listed?(addr, 'dnsbl.ahbl.org');       end
    def self.dsbl?(addr);    listed?(addr, 'list.dsbl.org');        end
    def self.njabl?(addr);   listed?(addr, 'combined.njabl.org');   end
    def self.ordb?(addr);    listed?(addr, 'relays.ordb.org');      end
    def self.sbl?(addr);     listed?(addr, 'sbl.spamhaus.org');     end
    def self.sbl_xbl?(addr); listed?(addr, 'sbl-xbl.spamhaus.org'); end
    def self.sorbs?(addr);   listed?(addr, 'dnsbl.sorbs.net');      end
    def self.spamcop?(addr); listed?(addr, 'bl.spamcop.net');       end
    def self.xbl?(addr);     listed?(addr, 'xbl.spamhaus.org');     end

  end

end; end
