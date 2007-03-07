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

class DenySpam; module Config

  @default = {
    :MAILLOG         => '/var/log/maillog',
    :HOSTDATA        => '/var/db/denyspam/hostdata',
    :BLOCK_COMMAND   => '/sbin/pfctl -t denyspam -T add :addresses > /dev/null 2>&1',
    :UNBLOCK_COMMAND => '/sbin/pfctl -t denyspam -T delete :addresses > /dev/null 2>&1',
    :FLUSH_COMMAND   => '/sbin/pfctl -t denyspam -T flush > /dev/null 2>&1',
    :BLOCK_MINUTES   => 30,
    :DEFAULT_SCORE   => -10,
    :RULES           => {},
    :ADVANCED_RULES  => {},

    # Undocumented config variables (change these at your own risk).
    :REGEXP_CONNECT    => / postfix\/smtpd\[(\d+)\]: connect from ([^\[]+)\[([\d\.]+)\]\s*$/,
    :PARAMS_CONNECT    => [:pid, :hostname, :ip],
    
    :REGEXP_DISCONNECT => / postfix\/smtpd\[(\d+)\]: disconnect from ([^\[]+)\[([\d\.]+)\]\s*$/,
    :PARAMS_DISCONNECT => [:pid, :hostname, :ip],
    
    :REGEXP_ENTRY      => / postfix\/smtpd\[(\d+)\]: (.*)$/,
    :PARAMS_ENTRY      => [:pid, :entry]
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
