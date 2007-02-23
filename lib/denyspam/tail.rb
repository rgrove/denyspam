module DenySpam

  # Provides <tt>tail -f</tt> functionality used to monitor a log file for
  # changes. Automatically reopens the file if it is truncated or deleted.
  class Tail

    attr_accessor :interval
    attr_reader :filename, :last_change, :last_pos

    def initialize(filename, interval = 10, start_pos = 0)
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
          Syslog::log(Syslog::LOG_DEBUG, 'previous position in %s is past ' +
              'the end of the file; restarting at the beginning',
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
          elsif Time.now - @last_change > 600
            # Reopen the file if it hasn't changed in over 10 minutes.
            Syslog::log(Syslog::LOG_DEBUG, "%s hasn't changed in over 10 " +
                "minutes; reopening the file just to be safe...",
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
          Syslog::log(Syslog::LOG_DEBUG, '%s appears to have been deleted; ' +
              'attempting to reopen', @filename)

          @last_stat = nil

          _reopen
        elsif stat.size < @last_stat.size
          Syslog::log(Syslog::LOG_DEBUG, '%s appears to have been truncated; ' +
              'attempting to reopen', @filename)

          @last_stat = nil

          _reopen
        end
      else
        @last_stat = stat
      end

    rescue Errno::ENOENT
    rescue Errno::ESTALE
      Syslog::log(Syslog::LOG_DEBUG, '%s appears to have been deleted; ' +
          'attempting to reopen', @filename)

      _reopen
    end

  end

end
