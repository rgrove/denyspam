#!/usr/bin/env ruby
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

# stdlib includes
require 'optparse'
require 'yaml'

# RubyGems includes
require 'rubygems'
require 'denyspam'

PREFIX = '/usr/local'

APP_NAME      = 'DenySpam'
APP_VERSION   = '1.0.0'
APP_COPYRIGHT = 'Copyright (c) 2007 Ryan Grove <ryan@wonko.com>. All rights reserved.'
APP_URL       = 'http://wonko.com/software/denyspam/'

module DenySpam

  options = {
    :config_file => ENV['DENYSPAM_CONF'] || File.join(PREFIX, 'etc',
        'denyspam.conf'),
    :command       => :start,
    :export_format => :yaml,
    :ip            => nil,
    :mode          => :monitor,
    :sort          => :ip,
    :sort_order    => :asc
  }
  
  optparse = OptionParser.new do |optparse|
    optparse.summary_width  = 24
    optparse.summary_indent = '  '
    
    optparse.banner = 'Usage: denyspam [options]'
    
    optparse.separator ''
    optparse.separator 'Options:'
    
    optparse.on('-c', '--config [filename]',
        'Use the specified configuration file.') do |filename|
      options[:config_file] = filename
    end
    
    optparse.on('-d', '--daemon [command]', [:start, :stop, :restart],
        'Issue the specified command (start, stop, or restart)',
        'to the ' + APP_NAME + ' daemon.') do |command|
      options[:command] = command
      options[:mode]    = :daemon
    end
    
    optparse.on('-i', '--info [ip]',
        'Display information about the specified IP address,',
        'or all addresses if no address is specified.') do |ip|
      options[:ip]   = ip
      options[:mode] = :info
    end
    
    optparse.on('-s', '--sort [column]', 
        [:ip, :score, :sessions, :seen, :blocked],
        'Sort information display by the specified column',
        '(ip, score, sessions, seen, or blocked) in',
        'ascending order.') do |column|
      options[:sort] = column
    end
    
    optparse.on('-S', '--sort-desc [column]', 
        [:ip, :score, :sessions, :seen, :blocked],
        'Sort information display by the specified column',
        '(ip, score, sessions, seen, or blocked) in',
        'descending order.') do |column|
      options[:sort]       = column
      options[:sort_order] = :desc
    end
    
    optparse.on('-x', '--export [format]',
        [:yaml, :xml],
        'Export host information in the specified format',
        '(yaml or xml).') do |format|
      options[:mode]          = :export
      options[:export_format] = format
    end
    
    optparse.on_tail('-h', '--help',
        'Display usage information (this message).') do
      puts optparse
      exit
    end
    
    optparse.on_tail('-v', '--version',
        'Display version information.') do
      puts "#{APP_NAME} v#{APP_VERSION} <#{APP_URL}>"
      puts "#{APP_COPYRIGHT}"
      puts
      puts "#{APP_NAME} comes with ABSOLUTELY NO WARRANTY."
      puts
      puts 'This program is open source software distributed under the BSD license. For'
      puts 'details, see the LICENSE file contained in the source distribution.'
      exit
    end
  end
  
  begin
    optparse.parse!(ARGV)
  rescue => e
    abort("Error: #{e}")
  end
  
  case options[:mode]
    when :daemon
      case options[:command]
        when :start
          start_daemon(File.expand_path(options[:config_file]))
          
        when :stop
          stop_daemon
          
        when :restart
          stop_daemon
          start_daemon(File.expand_path(options[:config_file]))
          
        else
          abort("** Error: invalid daemon command: #{options[:command]}")
      end  

    when :monitor
      # Start monitoring.
      start(options[:config_file])
      start_monitoring.join
    
    when :info
      ip = options[:ip]
      
      # Load config.
      Config.load_config(options[:config_file])
      
      # Load host data.
      load_data
      
      # Display statistics.
      puts 'IP              | Score   | Sessions | Last seen         | Blocked until'
      puts '----------------+---------+----------+-------------------+-------------------'

      case options[:sort]
        when :score
          hosts = @hosts.sort_by {|item| item[1].score }
          
        when :sessions
          hosts = @hosts.sort_by {|item| item[1].times_seen }
          
        when :seen
          hosts = @hosts.sort_by {|item| item[1].last_seen }
          
        when :blocked
          hosts = @hosts.sort_by do |item|
            item[1].blocked_until.nil? ? Time.at(0) : item[1].blocked_until
          end
          
        else
          hosts = @hosts.sort_by {|item| IPAddr.new(item[0]) }
      end
      
      hosts.reverse! if options[:sort_order] == :desc
      
      hosts.each do |host_ip, host|
        next unless ip.nil? || host_ip == ip
        
        puts format('%-15s | %7d | %8d | %-17s | %-17s',
            host.ip,
            host.score,
            host.times_seen,
            host.last_seen.nil? ? '' : host.last_seen.strftime('%b %d %H:%M %Z'),
            host.blocked_until.nil? ? '' : host.blocked_until.strftime('%b %d %H:%M %Z'))
      end

      exit
    
    when :export
      # Load config.
      Config.load_config(options[:config_file])
      
      # Load host data.
      load_data
      
      # Export data.
      if options[:export_format] == :yaml
        puts YAML.dump(@hosts)
      elsif options[:export_format] == :xml
        abort('** Error: xml export not yet implemented (sorry!)')
      end
  end
end
