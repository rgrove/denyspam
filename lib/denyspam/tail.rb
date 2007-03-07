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

module DenySpam

  # Provides <tt>tail -f</tt> functionality used to monitor a file for changes.
  # Automatically reopens the file if it is truncated or deleted.
  class Tail

    attr_accessor :interval
    attr_reader   :filename, :lastpos

    def initialize(filename, lastpos = 0, interval = 15)
      @filename  = filename
      @lastpos   = lastpos
      @interval  = interval
      @last_stat = nil
    end

    # Begins tailing the file. When a new line appears, it's passed to the
    # block.
    def tail(&block) # :yields: line
      # Wait for the file to be created if it doesn't already exist.
      until File.exist?(@filename)
        sleep 30
      end

      # Make sure the file isn't a directory.
      if File.directory?(@filename)
        if Syslog.opened?
          Syslog.log(Syslog::LOG_ERR, 'error: %s is a directory', @filename)
          Syslog.log(Syslog::LOG_INFO, 'shutting down')
          Syslog.close
        end

        abort "** Error: #{@filename} is a directory"
      end

      # Begin watching the file.
      File.open(@filename) do |@file|
        begin
          @file.pos = @lastpos if @lastpos > 0
        rescue EOFError
          @file.rewind
        end

        loop do
          restat

          while line = @file.gets
            @lastpos = @file.pos
            yield line
          end

          @file.seek(0, File::SEEK_CUR)

          sleep @interval
        end
      end
    end

    private

    # Reopens the file. This is necessary if the file is deleted or truncated
    # while we're watching it.
    def reopen
      @file.reopen(@filename)
      @lastpos = 0

      Syslog::log(Syslog::LOG_INFO, 'reopening %s', @filename)

    rescue Errno::ENOENT
    rescue Errno::ESTALE
      # File isn't there. Wait for it to reappear.
      sleep 15
      retry
    end

    # Performs various checks to determine whether we should reopen the file.
    def restat
      stat = File.stat(@filename)

      if !@last_stat.nil?
        if stat.ino != @last_stat.ino || stat.dev != @last_stat.dev
          # File was replaced. Reopen it.
          @last_stat = nil
          reopen
        elsif stat.size < @last_stat.size
          # File was truncated. Reopen it.
          @last_stat = nil
          reopen
        end
      else
        @last_stat = stat
      end

    rescue Errno::ENOENT
    rescue Errno::ESTALE
      # File was deleted. Attempt to reopen it.
      reopen
    end

  end
  
end
