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

require 'rubygems'
require 'denyspam'

PREFIX = '/usr/local'

APP_NAME    = 'DenySpam'
APP_VERSION = '1.0.0-beta'
APP_URL     = 'http://wonko.com/software/denyspam/'

CONFIG_FILE = ENV['DENYSPAM_CONF'] || File.join(PREFIX, 'etc', 'denyspam.conf')

# Open Syslog.
Syslog.open('denyspam', 0, Syslog::LOG_MAIL)

# Start DenySpam.
denyspam = DenySpam.new(CONFIG_FILE)
monitor_thread = denyspam.start_monitoring

# Setup signal handlers.
for sig in [:SIGINT, :SIGQUIT, :SIGTERM]
  trap(sig) { denyspam.stop_monitoring }
end

monitor_thread.join
