module DenySpam; module Config

  @default = {
    :MAILLOG        => '/var/log/maillog',
    :HOSTDATA       => '/usr/local/share/denyspam/hostdata',
    :PFCTL          => '/sbin/pfctl',
    :PF_TABLE       => 'denyspam',
    :BLOCK_MINUTES  => 30,
    :DEFAULT_SCORE  => -10,
    :RULES          => {},
    :ADVANCED_RULES => {},

    # Undocumented config variables (change these at your own risk).
    :REGEXP_ENTRY => /^.* (?:sendmail|sm-mta)\[\d+\]: (\w+): (.*)$/,
    :REGEXP_FROM  => /^from=.*, relay=.*\[([\d.]+)\].*$/,
  }

  def self.const_missing(name)
    return @default[name]
  end

  def self.load_config(config_file)
    load config_file if File.exist?(config_file)

  rescue Exception => e
    message = e.message.gsub("\n", '; ')

    if Syslog::opened?
      Syslog::log(Syslog::LOG_ERR, 'configuration error in %s: %s', config_file,
          message)
      Syslog::close
    end

    abort "Configuration error in #{config_file}: #{message}"
  end

end; end
