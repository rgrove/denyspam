#--
# Copyright (c) 2007 Ryan Grove <ryan@wonko.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions and the following disclaimer in the documentation
#     and/or other materials provided with the distribution.
#   * Neither the name of this project nor the names of its contributors may be
#     used to endorse or promote products derived from this software without
#     specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#++

# Append this file's directory to the include path if it's not there already.
unless $:.include?(File.dirname(__FILE__)) ||
    $:.include?(File.expand_path(File.dirname(__FILE__)))
  $:.unshift(File.dirname(__FILE__)) 
end
  
# stdlib includes
require 'fileutils'
require 'ipaddr'
require 'resolv'
require 'syslog'
require 'thread'
require 'time'
require 'yaml'

# RubyGems includes
require 'rubygems'
require 'kirbybase'

# DenySpam includes
require 'denyspam/config'
require 'denyspam/host'
require 'denyspam/tail'
require 'denyspam/util'
require 'denyspam/util/rbl'

class IPAddr
  def <=>(other_addr)
    @addr <=> other_addr.to_i
  end
end

class DenySpam

  VERSION = '1.0.0-beta'

  attr_reader :config_file, :hosts, :lastpos

  #--
  # Public Instance Methods
  #++
  
  def initialize(config_file)
    @threads = {}
    
    Config.load_config(config_file)
        
    load_data
    flush_table
    update_table
  end
  
  # Adds the specified IP address or array of addresses to the firewall's block
  # table.
  def block(addresses)
    if addresses.is_a? Array
      system(set_params(Config::BLOCK_COMMAND, :addresses => addresses.join(' ')))
    else
      system(set_params(Config::BLOCK_COMMAND, :addresses => addresses))
    end
  end
  
  # Clears all hosts from the firewall's block table.
  def flush_table
    system(Config::FLUSH_COMMAND)
  end
  
  # Starts monitoring the mail server log.
  def start_monitoring
    # Unblock thread (unblocks hosts when their block times have expired).
    @threads[:unblock] = Thread.new do
      loop do
        sleep 60
        
        now       = Time.now
        unblocked = []
        
        # TODO: Use a binary tree lookup instead of doing a linear search.
        @hosts.each_value do |host|
          next if host.blocked_until.nil?
          
          if host.blocked_until <= now
            host.blocked_until = nil
            unblocked << host.ip
          end
        end
        
        unblock(unblocked) if unblocked.length > 0
      end
    end
    
    # Data writing thread. Writes DenySpam data to disk at regular intervals if
    # it has changed since the last write.
    @threads[:data] = Thread.new do      
      # TODO: Use an on-disk database instead of storing the host data in memory.      
      loop do
    		save_data
        sleep 120
      end
    end
  end
  
  # Stops monitoring the mail server log.
  def stop_monitoring
  end
  
  # Removes the specified IP address or array of addresses from the firewall's
  # block table.
  def unblock(addresses)
    if addresses.is_a? Array
      system(set_params(Config::UNBLOCK_COMMAND, :addresses => addresses.join(' ')))
    else
      system(set_params(Config::UNBLOCK_COMMAND, :addresses => addresses))
    end
  end
  
  # Updates the firewall's block table, blocking hosts that need to be blocked
  # and unblocking hosts whose block time has expired.
  def update_table
    now       = Time.now
    blocked   = []
    unblocked = []
    
    @hosts.each_value do |host|
      next if host.blocked_until.nil?
      
      if host.blocked_until > now
        blocked << host.ip
      elsif host.blocked_until <= now
        host.blocked_until = nil
        unblocked << host.ip
      end
    end
    
    block(blocked) if blocked.length > 0
    unblock(unblocked) if unblocked.length > 0
  end
  
  #--
  # Private Instance Methods
  #++

  private
  
  # Loads DenySpam data from disk.
  def load_data
    if File.exist?(Config::HOSTDATA)
      data = YAML.load_file(Config::HOSTDATA)
      
      @lastpos = data[:lastpos]
      @hosts   = data[:hosts]
    else
      @lastpos = 0
      @hosts   = {}
    end
  
  rescue Exception => e
    if Syslog.opened?
      Syslog.log(Syslog.LOG_ERR, 'error loading data: %s', e)
    end
    
    abort "** Error loading data: #{e}"
  end
  
  # Saves DenySpam data to disk.
  def save_data
    # Create the containing directory if it doesn't exist.
    unless File.exist?(File.dirname(Config::HOSTDATA))
      FileUtils.mkdir_p(File.dirname(Config::HOSTDATA))
    end
    
    data = {
      :lastpos => @lastpos,
      :hosts   => @hosts
    }
    
    File.open(Config::HOSTDATA, 'w') {|file| YAML.dump(data, file) }
    
  rescue Exception => e
    if Syslog.opened?
      Syslog.log(Syslog::LOG_ERR, 'error saving data: %s', e)
    else
      STDERR.puts "** Error saving data: #{e}"
    end
  end
  
  # Replaces parameters (e.g. :param) in the given string with the specified
  # values, escaping them if necessary, and returns the resulting string.
  def set_params(string, params = {})
    params.each do |key, value|
      if value =~ /\W/
        value = "'" + value.gsub("'", "\\'") + "'"
      end
      
      string.gsub(':' + key.to_s, value)
    end
    
    return string
  end

end
