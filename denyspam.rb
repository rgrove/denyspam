#!/usr/bin/env ruby
#
# = DenySpam
#
# Monitors a Sendmail log file and uses Packet Filter to temporarily block or
# redirect incoming packets from hosts that display spammer-like behavior.
#
# Version::   1.0.0-beta
# Author::    Ryan Grove (mailto:ryan@wonko.com)
# Copyright:: Copyright (c) 2005 Ryan Grove
# License::   DenySpam is open source software distributed under the terms of
#             the GNU General Public License.
# Website::   http://wonko.com/software/denyspam
#
# === Dependencies
#
# * Ruby[http://ruby-lang.org/] 1.8.2
# * {Packet Filter}[http://openbsd.org/faq/pf/] (if you're running a recent
#   version of OpenBSD, FreeBSD, NetBSD, or DragonFlyBSD, you probably already
#   have PF installed)
#
# :title: DenySpam
#
# $Id: denyspam.rb,v 1.11 2005/08/29 21:19:36 ryan Exp $
#

#$DEBUG = true

PREFIX = '/usr/local'

require 'fileutils'
require 'ipaddr'
require 'resolv'
require 'syslog'
require 'thread'
require 'time'

class IPAddr

	def <=>(other_addr)
		@addr <=> other_addr.to_i
	end

end # class IPAddr

module DenySpamConfig

	@default = {
		:SENDMAIL_LOGFILE => '/var/log/maillog',
		:HOSTDATA         => '/usr/local/share/denyspam/hostdata',
		:PFCTL            => '/sbin/pfctl',
		:PF_TABLE         => 'denyspam',
		:BLOCK_MINUTES    => 10,
		:DEFAULT_SCORE    => -10,
		:RULES            => {},
		:ADVANCED_RULES   => {},

		# Undocumented config variables (change these at your own risk).
		:REGEXP_ENTRY => /^.* (?:sendmail|sm-mta)\[\d+\]: (\w+): (.*)$/,
		:REGEXP_FROM  => /^from=.*, relay=.*\[([\d.]+)\].*$/,
	}

	def self.const_missing(name)
		@default[name]
	end

	def self.load_config(config_file)
		load config_file if File.exist?(config_file)

	rescue Exception => e
		message = e.message.gsub("\n", '; ')

		if Syslog::opened?
			Syslog::log(Syslog::LOG_ERR, 'configuration error in %s: %s',
				config_file, message)
			Syslog::close

			abort
		else
			abort "Configuration error in #{config_file}: #{message}"
		end
	end

end # module DenySpamConfig

# DenySpam monitors a Sendmail log file and uses Packet Filter to temporarily
# block or redirect incoming packets from hosts that display spammer-like
# behavior.
#
# See http://wonko.com/software/denyspam for details.
module DenySpam

	APP_NAME    = 'DenySpam'
	APP_VERSION = '1.0.0-beta'

	# Provides some useful utility methods that may come in handy for advanced
	# rules.
	module Util

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

		end # module RBL

	end # module Util


	# Represents a remote mail server.
	class Host

		attr_accessor :blocked_since, :blocked_until, :score
		attr_reader :addr, :last_seen, :times_seen

		def initialize(addr)
			@addr          = addr
			@blocked_since = nil
			@blocked_until = nil
			@last_seen     = nil
			@score         = DenySpamConfig::DEFAULT_SCORE
			@times_seen    = 0
		end

		# Returns <i>true</i> if the host is currently blocked, <i>false</i>
		# otherwise.
		def blocked?
			return !@blocked_until.nil?
		end

		# Returns <i>true</i> if the host is not currently blocked and hasn't been
		# seen in over one week, <i>false</i> otherwise.
		def old?
			return blocked? == false && Time.now - @last_seen > 604800
		end

		# Updates the host's <i>last_seen</i> time and increments <i>times_seen</i>
		# by one.
		def seen
			@last_seen   = Time.now
			@times_seen += 1
		end

		# Returns <i>true</i> if the host is suspected of being a spammer,
		# <i>false</i> otherwise.
		def spammer?
			return @score > 0
		end

	end # class Host

	# Provides <tt>tail -f</tt> functionality used to monitor the Sendmail log
	# for changes. Automatically reopens the file if it is truncated or deleted.
	class Tail

		attr_accessor :interval
		attr_reader :filename, :last_change, :last_pos

		def initialize(filename, interval = 5, start_pos = 0)
			@filename    = filename
			@interval    = interval
			@last_change = Time.now
			@last_pos    = 0
			@last_stat   = nil
			@start_pos   = start_pos
		end

		# Begins tailing the file. When a new line appears, it's passed to the
		# block.
		def tail(&block) # :yields: line
			unless File.exist?(@filename)
				Syslog::log(Syslog::LOG_DEBUG,
					'%s does not exist; waiting for it to be created', @filename)

				until File.exist?(@filename)
					sleep 10
				end

				Syslog::log(Syslog::LOG_DEBUG, '%s has been created', @filename)
			end

			if File.directory?(@filename)
				Syslog::log(Syslog::LOG_ERR, 'error: %s is a directory; aborting',
					@filename)
				Syslog::close

				abort "** Error: #{@filename} is a directory"
			end

			File.open(@filename) do |@file|
				begin
					@file.pos = @start_pos if @start_pos > 0

				rescue EOFError
					Syslog::log(Syslog::LOG_DEBUG,
						'previous position in %s is past the end of the file; restarting at the beginning',
						@filename)

					@file.rewind
				end

				loop do
					_restat

					changed = false

					while line = @file.gets
						changed = true
						yield line
					end

					if changed
						@last_change = Time.now
						@last_pos    = @file.pos
					elsif Time.now - @last_change > 600 # Reopen the file if it hasn't
						Syslog::log(Syslog::LOG_DEBUG,    # changed in over 10 minutes.
							"%s hasn't changed in over 10 minutes; reopening the file just to be safe...",
							@filename)

						_reopen
					end

					@file.seek(0, File::SEEK_CUR)

					sleep @interval
				end
			end
		end

		private

		# Reopens the file. This is necessary if the file is deleted or truncated
		# while we're watching it.
		def _reopen
			@file.reopen(@filename)

			@last_change = Time.now
			@last_pos    = 0

			Syslog::log(Syslog::LOG_DEBUG, '%s has been reopened', @filename)

		rescue Errno::ENOENT
		rescue Errno::ESTALE
			sleep 10
			retry

		end

		# Performs various checks to determine whether we should reopen the file.
		def _restat
			stat = File.stat(@filename)

			if @last_stat
				if stat.ino != @last_stat.ino || stat.dev != @last_stat.dev
					Syslog::log(Syslog::LOG_DEBUG,
						'%s appears to have been deleted; attempting to reopen', @filename)

					@last_stat = nil

					_reopen
				elsif stat.size < @last_stat.size
					Syslog::log(Syslog::LOG_DEBUG,
						'%s appears to have been truncated; attempting to reopen', @filename)

					@last_stat = nil

					_reopen
				end
			else
				@last_stat = stat
			end

		rescue Errno::ENOENT
		rescue Errno::ESTALE
			Syslog::log(Syslog::LOG_DEBUG,
				'%s appears to have been deleted; attempting to reopen', @filename)

			_reopen
		end

	end # class Tail


	# Lots of fun variables that hold all kinds of nifty information.
	@last_pos = 0
	@blocked  = []
	@threads  = {}

	@hosts = Hash.new {|hash, addr| hash[addr] = Host.new(addr) }

	@sessions = Hash.new do |hash, session_id|
		hash[session_id] = {
			:addr   => nil,
			:buffer => [],
			:seen   => Time.now,
		}
	end

	# Blocks <i>addr</i> until <i>expire_time</i>.
	def self.block(addr, expire_time, *options)
		nolog   = options.include?(:nolog)
		nosort  = options.include?(:nosort)
		nopfctl = options.include?(:nopfctl)

		host = @hosts[addr]

		@blocked << addr

		if host.blocked?
			host.blocked_until = expire_time

			Syslog::log(Syslog::LOG_INFO, 'extending block for %s to %s',
				addr, expire_time.strftime('%b %d %H:%M:%S')) unless nolog
		else
			host.blocked_since = Time.now
			host.blocked_until = expire_time

			unless nopfctl
				if system("#{DenySpamConfig::PFCTL} -t \"#{DenySpamConfig::PF_TABLE}\" -T add \"#{addr}\" > /dev/null 2>&1")
					Syslog::log(Syslog::LOG_INFO, 'blocking %s until %s',
						addr, expire_time.strftime('%b %d %H:%M:%S')) unless nolog
				else
					Syslog::log(Syslog::LOG_ERR,
						'unable to block %s: pfctl command failed', addr) unless nolog
				end
			end
		end

		_sort_blocklist unless nosort
	end

	# Loads host data from the file specified by <i>filename</i>.
	def self.load_hosts(filename = DenySpamConfig::HOSTDATA)
		return false unless File.exist?(filename)

		Syslog::log(Syslog::LOG_DEBUG, 'loading host data from %s', filename)

		data = Marshal.load(File.read(filename))

		unless data[:version] == APP_VERSION
			Syslog::log(Syslog::LOG_WARNING,
				'host data in %s is not compatible with this version of %s',
				filename, APP_NAME)

			return false
		end

		@last_pos = data[:last_pos]

		# Build the host list.
		now = Time.now

		data[:hosts].each do |host|
			if host.blocked?
				if host.blocked_until <= now
					host.blocked_since = nil
					host.blocked_until = nil
				else
					block(host.addr, host.blocked_until, :nolog, :nosort, :nopfctl)
				end
			end

			@hosts[host.addr] = host
		end

		_sort_blocklist

		system("#{DenySpamConfig::PFCTL} -t \"#{DenySpamConfig::PF_TABLE}\" -T add #{@blocked.join(' ')} > /dev/null 2>&1")

	rescue Exception
		Syslog::log(Syslog::LOG_ERR, 'host data in %s is corrupt or invalid',
			filename)

		@last_pos = 0
		@hosts.clear

		return false

	end

	# Main program loop. Monitors the Sendmail log (as configured in
	# <tt>denyspam.conf</tt>) for changes and applies rules when new log entries
	# appear.
	def self.monitor
		Syslog::log(Syslog::LOG_INFO, 'monitoring %s',
			DenySpamConfig::SENDMAIL_LOGFILE)

		# Unblock thread (unblocks hosts when their block times expire).
		@threads[:unblock] = Thread.new do
			loop do
				unless @blocked.empty?
					now = Time.now

					while @hosts[@blocked.first].blocked_until <= now
						unblock(@blocked.first)
					end
				end

				sleep 60
			end
		end

		# Maintenance thread.
		@threads[:maint] = Thread.new do
			loop do
				sleep 300

				_clean_hosts
				_clean_sessions

				save_hosts

				Util::RBL::clean_cache
			end
		end

		# Start watching the Sendmail log.
		@tail = Tail.new(DenySpamConfig::SENDMAIL_LOGFILE, 5, @last_pos)

		@tail.tail do |line|
			next unless line =~ DenySpamConfig::REGEXP_ENTRY
			_apply_rules(_update_session($1, $2))
		end
	end

	# Saves current host data to the file specified by <i>filename</i>. The
	# file and its directory structure will be created if they do not exist.
	def self.save_hosts(filename = DenySpamConfig::HOSTDATA)
		return false if filename.nil? || filename.empty?

		unless File.exist?(File.dirname(filename))
			Syslog::log(Syslog::LOG_DEBUG, 'creating directory %s',
				File.dirname(filename))

			FileUtils.mkdir_p(File.dirname(filename))
		end

		data = {
			:version  => APP_VERSION,
			:last_pos => @tail.last_pos,
			:hosts    => @hosts.values
		}

		File.open(filename, 'w') do |file|
			Marshal.dump(data, file)
		end

		return true

	rescue Exception => e
		Syslog::log(Syslog::LOG_ERR, 'error saving host data to %s: %s',
			filename, e.message.gsub("\n", '; '))

		return false

	end

	# Opens a connection to syslog and loads the config file and host data file,
	# but does not actually begin monitoring the Sendmail log. See
	# DenySpam::monitor.
	def self.start
		Dir.chdir '/'
		File.umask 0000

		Syslog::open('denyspam', 0, Syslog::LOG_MAIL)

		unless $DEBUG
			STDIN.reopen('/dev/null')
			STDOUT.reopen('/dev/null', 'a')
			STDERR.reopen(STDOUT)
		end

		_set_signal_handlers

		DenySpamConfig::load_config(ENV['DENYSPAM_CONF'] ||
			File.join(PREFIX, 'etc/denyspam.conf'))

		load_hosts
	end

	# Stops DenySpam.
	def self.stop
		save_hosts

		if @blocked && !@blocked.empty?
			system("#{DenySpamConfig::PFCTL} -t \"#{DenySpamConfig::PF_TABLE}\" -T delete #{@blocked.join(' ')} > /dev/null 2>&1")

			while addr = @blocked.shift
				unblock(addr, :nolog, :nopfctl)
			end
		end

		Syslog::log(Syslog::LOG_INFO, 'exiting')
		Syslog::close

		exit
	end

	# Unblocks the specified IP address.
	def self.unblock(addr, *options)
		nolog   = options.include?(:nolog)
		nopfctl = options.include?(:nopfctl)

		host = @hosts[addr]

		host.blocked_since = nil
		host.blocked_until = nil

		@blocked.delete(addr)

		unless nopfctl
			if system("#{DenySpamConfig::PFCTL} -t \"#{DenySpamConfig::PF_TABLE}\" -T delete \"#{addr}\" > /dev/null 2>&1")
				Syslog::log(Syslog::LOG_INFO, 'unblocking %s', addr) unless nolog
			else
				Syslog::log(Syslog::LOG_ERR,
					'unable to unblock %s: pfctl command failed', addr) unless nolog
			end
		end
	end

	private

	def self._apply_rules(session)
		addr = session[:addr] or return false

		return false if addr == '127.0.0.1'

		host = @hosts[addr]
		host.seen

		while message = session[:buffer].shift do
			# Apply simple rules (regular expressions).
			DenySpamConfig::RULES.each_pair do |points, rules|
				rules.each {|rule| host.score += points if message =~ rule }
			end

			# Apply advanced rules (Ruby procs).
			begin
				DenySpamConfig::ADVANCED_RULES.each_pair do |points, rules|
					rules.each do |rule|
						host.score += points if rule[host.dup, message.dup]
					end
				end

			rescue Exception => e
				Syslog::log(Syslog::LOG_ERR, 'rule error: %s',
					e.message.gsub("\n", '; '))

			end
		end

		if host.score > 65536
			host.score = 65536
		elsif host.score < -65536
			host.score = -65536
		end

		if host.spammer?
			block(addr, Time.now + ((DenySpamConfig::BLOCK_MINUTES * 60) *
				host.score))
		end

		return true
	end

	# Deletes hosts that aren't blocked and haven't been seen in over a week.
	def self._clean_hosts
		@hosts.delete_if {|addr, host| host.old? }
	end

	# Deletes old sessions to free memory.
	def self._clean_sessions
		now = Time.now

		@sessions.delete_if do |session_id, session|
			(session[:addr].nil? || session[:buffer].empty?) &&
				now - session[:seen] >= 600
		end
	end

	def self._set_signal_handlers
		for sig in [:SIGINT, :SIGQUIT, :SIGTERM]
			trap(sig) { stop }
		end
	end

	def self._sort_blocklist
		@blocked.uniq!
		@blocked.sort! do |a, b|
			@hosts[a].blocked_until <=> @hosts[b].blocked_until
		end
	end

	def self._update_session(session_id, message)
		session = @sessions[session_id]

		session[:buffer] << message

		if session[:addr].nil? && message =~ DenySpamConfig::REGEXP_FROM
			session[:addr] = $1
		end

		return session
	end

	if __FILE__ == $0
		start
		monitor
	end

end # module DenySpam
