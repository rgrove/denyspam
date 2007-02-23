PREFIX = '/usr/local'

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

  VERSION = '1.0.0-beta'

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
        if system("#{Config::PFCTL} -t \"#{Config::PF_TABLE}\" -T add \"#{addr}\" > /dev/null 2>&1")
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
  def self.load_hosts(filename = Config::HOSTDATA)
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

    system("#{Config::PFCTL} -t \"#{Config::PF_TABLE}\" -T add #{@blocked.join(' ')} > /dev/null 2>&1")

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
    Syslog::log(Syslog::LOG_INFO, 'monitoring %s', Config::MAILLOG)

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

    # Start watching the mail log.
    @tail = Tail.new(Config::MAILLOG, 10, @last_pos)

    @tail.tail do |line|
      next unless line =~ Config::REGEXP_ENTRY
      _apply_rules(_update_session($1, $2))
    end
  end

  # Saves current host data to the file specified by <i>filename</i>. The
  # file and its directory structure will be created if they do not exist.
  def self.save_hosts(filename = Config::HOSTDATA)
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

    Config::load_config(ENV['DENYSPAM_CONF'] ||
        File.join(PREFIX, 'etc/denyspam.conf'))

    load_hosts
  end

  # Stops DenySpam.
  def self.stop
    save_hosts

    if @blocked && !@blocked.empty?
      system("#{Config::PFCTL} -t \"#{Config::PF_TABLE}\" -T delete #{@blocked.join(' ')} > /dev/null 2>&1")

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
      if system("#{Config::PFCTL} -t \"#{Config::PF_TABLE}\" -T delete \"#{addr}\" > /dev/null 2>&1")
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
      Config::RULES.each_pair do |points, rules|
        rules.each {|rule| host.score += points if message =~ rule }
      end

      # Apply advanced rules (Ruby procs).
      begin
        Config::ADVANCED_RULES.each_pair do |points, rules|
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
      block(addr, Time.now + ((Config::BLOCK_MINUTES * 60) *
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

    if session[:addr].nil? && message =~ Config::REGEXP_FROM
      session[:addr] = $1
    end

    return session
  end

end
