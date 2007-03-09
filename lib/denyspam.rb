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

module DenySpam

  PIDFILE = '/var/run/denyspam.pid'

  @connections = {}
  @hosts       = {}
  @lastpos     = 0
  @monitoring = false
  @threads     = {}

  #--
  # Public Module Methods
  #++
  
  # Adds the specified IP address or array of addresses to the firewall's block
  # table.
  def self.block(addresses)
    if addresses.is_a?(Array)
      system(set_params(Config::BLOCK_COMMAND, :addresses => addresses.join(' ')))
    else
      system(set_params(Config::BLOCK_COMMAND, :addresses => addresses))
      
      if Syslog.opened?
        Syslog.log(Syslog::LOG_INFO, 'blocked %s', addresses)
      end
    end
  end
  
  # Clears all hosts from the firewall's block table.
  def self.flush_table
    system(Config::FLUSH_COMMAND)
  end
  
  # Loads DenySpam data from disk.
  def self.load_data
    if File.exist?(Config::HOSTDATA)
      data = {}
      
      File.open(Config::HOSTDATA, 'r') {|file| data = Marshal.load(file) }
      
      @lastpos = data[:lastpos]
      @hosts   = data[:hosts]
    else
      @lastpos = 0
      @hosts   = {}
    end
  
  rescue Exception => e
    if Syslog.opened?
      Syslog.log(Syslog::LOG_ERR, 'error loading data: %s', e)
    end
    
    abort "** Error loading data: #{e}"
  end
  
  # Saves DenySpam data to disk.
  def self.save_data
    # Create the containing directory if it doesn't exist.
    unless File.exist?(File.dirname(Config::HOSTDATA))
      FileUtils.mkdir_p(File.dirname(Config::HOSTDATA))
    end
    
    data = {
      :lastpos => @lastpos,
      :hosts   => @hosts
    }
    
    File.open(Config::HOSTDATA, 'w') {|file| Marshal.dump(data, file) }
    
  rescue Exception => e
    if Syslog.opened?
      Syslog.log(Syslog::LOG_ERR, 'error saving data: %s', e)
    else
      STDERR.puts "** Error saving data: #{e}"
    end
  end
  
  # Opens the syslog and loads the config file and host data.
  def self.start(config_file)
    Syslog.open('denyspam', 0, Syslog::LOG_MAIL)
    
    for sig in [:SIGINT, :SIGQUIT, :SIGTERM]
      trap(sig) { stop }
    end
    
    Config.load_config(config_file)

    load_data
    flush_table
    update_table
  end
  
  # Starts a DenySpam daemon.
  def self.start_daemon(config_file)
    # Check the pid file to see if the app is already running.
    if File.file?(PIDFILE)
      pid = File.read(PIDFILE, 20).strip
      abort("denyspam already running? (pid=#{pid})")
    end
    
    puts "Starting denyspam."
    
    # Fork off and die.
    fork do
      Process.setsid
      exit if fork
      
      # Write pid file.
      File.open(PIDFILE, 'w') {|file| file << Process.pid }
      
      # Release old working directory.
      Dir.chdir('/')
      
      # Reset umask.
      File.umask(0000)
      
      # Disconnect file descriptors.
      STDIN.reopen('/dev/null')
      STDOUT.reopen('/dev/null', 'a')
      STDERR.reopen(STDOUT)
      
      # Start monitoring.
      start(config_file)
      start_monitoring.join
    end
  end
  
  # Starts monitoring the mail server log.
  def self.start_monitoring
    @monitoring = true
    
    if Syslog.opened?
      Syslog.log(Syslog::LOG_INFO, 'started monitoring %s', Config::MAILLOG)
    end
    
    # Unblock thread (unblocks hosts when their block times have expired).
    @threads[:unblock] = Thread.new do
      loop do
        sleep 60
        
        now = Time.now
        
        # TODO: Use a binary tree lookup instead of doing a linear search.
        @hosts.each_value do |host|
          next if host.blocked_until.nil?
          
          if host.blocked_until <= now
            host.blocked_until = nil
            unblock(host.ip)
          end
        end
      end
    end
    
    # Data thread. Discards old data and writes host data to disk at regular
    # intervals. Also cleans up the RBL cache.
    @threads[:data] = Thread.new do      
      # TODO: Use an on-disk database instead of storing the host data in memory.
      # TODO: Don't write host data to disk if it hasn't changed since the last write.
      loop do
    		clean_hosts
    		clean_connections
    		save_data

        Util::RBL.clean_cache
        
        sleep 60
      end
    end
    
    # Monitors the mail server log for changes.
    @threads[:monitor] = Thread.new do
      tail = Tail.new(Config::MAILLOG, @lastpos)
      
      tail.tail do |line|
        @lastpos = tail.lastpos
        parse_entry(line)
      end
    end
    
    return @threads[:monitor]
  end
  
  # Stops monitoring, saves host data to disk, closes the syslog, and exits.
  def self.stop
    stop_monitoring    
    save_data
    flush_table
    
    Syslog.close if Syslog.opened?
    
    exit
  end
  
  # Stops the running DenySpam daemon. Aborts with an error message if no daemon
  # is currently running.
  def self.stop_daemon
    unless File.file?(PIDFILE)
      abort("denyspam not running? (check #{PIDFILE}).")
    end
    
    puts 'Stopping denyspam.'
    
    pid = File.read(PIDFILE, 20).strip
    FileUtils.rm(PIDFILE)
    pid && Process.kill('TERM', pid.to_i)    
  end
  
  # Stops monitoring the mail server log.
  def self.stop_monitoring
    return unless @monitoring
    
    @threads.each {|name, thread| thread.kill }
    
    if Syslog.opened?
      Syslog.log(Syslog::LOG_INFO, 'stopped monitoring %s', Config::MAILLOG)
    end
    
    @monitoring = false
  end
  
  # Removes the specified IP address or array of addresses from the firewall's
  # block table.
  def self.unblock(addresses)
    if addresses.is_a?(Array)
      system(set_params(Config::UNBLOCK_COMMAND, :addresses => addresses.join(' ')))
    else
      system(set_params(Config::UNBLOCK_COMMAND, :addresses => addresses))
      
      if Syslog.opened?
        Syslog.log(Syslog::LOG_INFO, 'unblocked %s', addresses)
      end
    end
  end
  
  # Updates the firewall's block table, blocking hosts that need to be blocked
  # and unblocking hosts whose block time has expired.
  def self.update_table
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
    
    Config::BLACKLIST.each do |ip|
      blocked << ip
    end
    
    block(blocked) if blocked.length > 0
    unblock(unblocked) if unblocked.length > 0
  end
  
  #--
  # Private Module Methods
  #++

  private
  
  # Tests DenySpam rules against the specified connection hash and modified the
  # host's score as necessary.
  def self.apply_rules(conn)
    return false if conn[:ip].nil? || conn[:buffer].empty?
    return true if Config::WHITELIST.include?(conn[:ip])
    
    host = @hosts[conn[:ip]] ||= Host.new(conn[:ip])
    
    while entry = conn[:buffer].shift do
      # Apply standard rules (regular expressions).
      Config::RULES.each do |points, rules|
        rules.each {|rule| host.score += points if entry =~ rule }
      end
      
      # Apply advanced rules (Ruby procs).
      begin
        Config::ADVANCED_RULES.each do |points, rules|
          rules.each do |rule|
            host.score += points if rule[host.dup, entry.dup]
          end
        end

      rescue => e
        if Syslog.opened?
          Syslog.log(Syslog::LOG_ERR, 'invalid rule: %s',
              e.message.gsub("\n", '; '))
        else
          STDERR.puts "** Error: invalid rule: #{e.message}"
        end
      end
    end
    
    if host.score > 65536
      host.score = 65536
    elsif host.score < -65536
      host.score = -65536
    end
    
    if host.spammer?
      unless host.blocked?
        host.blocked_since = Time.now
        block(host.ip)
      end
      
      host.blocked_until = Time.now + (Config::BLOCK_MINUTES * 60 * host.score)
    end
    
    return true
  end
  
  # Forgets stalled mail server connections.
  def self.clean_connections
    now = Time.now    
    @connections.delete_if {|pid, conn| now - conn[:seen] >= 900 }
  end
  
  # Forgets hosts that aren't blocked and haven't been seen in a while.
  def self.clean_hosts
    @hosts.delete_if {|ip, host| host.old? }
  end

  # Returns a hash with entries populated from the most recent regular
  # expression match, named according to the specified parameter array.
  def self.get_match_params(matchdata, param_names)
    return {} if matchdata.nil?
    
    params = {}
    
    param_names.each_index do |index|
      params[param_names[index]] = matchdata[index + 1]
    end
    
    return params
  end
  
  def self.parse_entry(line)
    case line
      when Config::REGEXP_CONNECT
        params = get_match_params($~, Config::PARAMS_CONNECT)
        
        @connections[params[:pid]] = {
          :buffer   => [],
          :hostname => params[:hostname],
          :ip       => params[:ip],
          :seen     => Time.now
        }
        
        unless params[:ip].nil?
          host = @hosts[params[:ip]] ||= Host.new(params[:ip])
          host.seen
        end
        
      when Config::REGEXP_DISCONNECT
        params = get_match_params($~, Config::PARAMS_DISCONNECT)        
        conn   = @connections.delete(params[:pid])
        
        unless conn.nil?
          conn[:hostname] ||= params[:hostname] unless params[:hostname].nil?
          conn[:ip]       ||= params[:ip] unless params[:ip].nil?
          conn[:seen]     =   Time.now
          
          apply_rules(conn)
        end
      
      when Config::REGEXP_ENTRY
        params = get_match_params($~, Config::PARAMS_ENTRY)
        conn   = @connections[params[:pid]]
        
        return false if conn.nil?
        
        conn[:buffer]   <<  params[:entry]
        conn[:hostname] ||= params[:hostname] unless params[:hostname].nil?
        conn[:ip]       ||= params[:ip] unless params[:ip].nil?
        conn[:seen]     =   Time.now
        
        apply_rules(conn)
        
      else
        return false
    end
    
    return true
  end
  
  # Replaces parameters (e.g. :param) in the given string with the specified
  # values and returns the resulting string.
  def self.set_params(string, params = {})
    params.each do |key, value|
      string = string.gsub(':' + key.to_s, value)
    end
    
    return string
  end

end
