module DenySpam;

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

  end

end
