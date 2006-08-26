#!/usr/bin/env ruby
# $Id: denyspamtool.rb,v 1.1 2005/08/24 00:56:34 ryan Exp $

require 'denyspam'

module DenySpam

	require 'optparse'

	DenySpamConfig::load_config(ENV['DENYSPAM_CONF'] ||
		File.join(PREFIX, 'etc/denyspam.conf'))

	data = Marshal.load(File.read(DenySpamConfig::HOSTDATA))

	data[:hosts].each {|host| @hosts[host.addr] = host }

	optparse = OptionParser.new do |optparse|
		optparse.summary_width  = 24
		optparse.summary_indent = '  '

		optparse.banner = 'Usage: denyspamtool [options]'

		optparse.separator 'Options:'

		optparse.on('-s', '--stats [sortcolumn]',
			'Display host statistics. If the optional sort',
			'argument is given the list will be sorted by the',
			'specified column.') do |sortcolumn|

			puts 'Host            | Score   | Sessions | Last seen         | Blocked until'
			puts '----------------+---------+----------+-------------------+-------------------'

			sortcolumn = '' if sortcolumn.nil?

			case sortcolumn.downcase
				when 'score'
					hosts = @hosts.sort_by {|item| item[1].score }

				when 'sessions', 'times seen', 'timesseen', 'times_seen'
					hosts = @hosts.sort_by {|item| item[1].times_seen }

				when 'seen', 'last seen', 'lastseen', 'last_seen'
					hosts = @hosts.sort_by {|item| item[1].last_seen }

				when 'blocked', 'blocked until', 'blockeduntil', 'blocked_until'
					# Pretend that non-blocked hosts are blocked until 2039 so they'll
					# end up sorted below blocked hosts in the list. In my opinion,
					# this is more intuitive than having blocked hosts show up last.
					# - Ryan
					the_future = Time.mktime(2038)

					hosts = @hosts.sort_by do |item|
						item[1].blocked_until.nil? ? the_future : item[1].blocked_until
					end

				else
					hosts = @hosts.sort_by {|item| IPAddr.new(item[0]) }
			end

			hosts.each do |addr, host|
				puts format('%-15s | %7d | %8d | %-17s | %-17s',
					host.addr,
					host.score,
					host.times_seen,
					host.last_seen.nil? ? '' : host.last_seen.strftime('%b %d %H:%M %Z'),
					host.blocked_until.nil? ? '' : host.blocked_until.strftime('%b %d %H:%M %Z'))
			end

			exit
		end

		optparse.on_tail('-h', '--help',
			'Display usage information (this message).') do
			puts optparse
			exit
		end

		optparse.on_tail('-v', '--version',
			'Display version information.') do
			puts "#{APP_NAME} v#{APP_VERSION} <http://wonko.com/software/denyspam/>"
			puts 'Copyright (c) 2005 Ryan Grove <ryan@wonko.com>.'
			puts
			puts "#{APP_NAME} comes with ABSOLUTELY NO WARRANTY."
			puts
			puts 'This program is open source software distributed under the terms of the'
			puts 'GNU General Public License. For details, see the LICENSE file contained in'
			puts 'the source distribution.'
			exit
		end
	end

	begin
		optparse.parse!(ARGV)
	rescue => e
		abort("Error: #{e}")
	end

	puts optparse

end # module DenySpam