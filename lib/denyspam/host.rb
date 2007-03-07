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

class DenySpam;

  # Represents a remote mail server.
  class Host

    attr_accessor :blocked_since, :blocked_until, :score
    attr_reader :ip, :last_seen, :times_seen

    def initialize(ip)
      @ip            = ip
      @blocked_since = nil
      @blocked_until = nil
      @last_seen     = nil
      @score         = Config::DEFAULT_SCORE
      @times_seen    = 0
    end

    # Returns _true_ if this host is currently blocked, _false_ otherwise.
    def blocked?
      return !@blocked_until.nil?
    end

    # Returns _true_ if this host is not currently blocked and hasn't been seen
    # in over 90 days, _false_ otherwise.
    def old?
      return !blocked? && Time.now - @last_seen > 7776000
    end

    # Updates the host's _last_seen_ time and increments _times_seen_ by one.
    def seen
      @last_seen   = Time.now
      @times_seen += 1
    end

    # Returns _true_ if the host is suspected of being a spammer, _false_
    # otherwise.
    def spammer?
      return @score > 0
    end

  end

end
