require 'rubygems'

Gem::manage_gems

require 'rake/gempackagetask'
require 'rake/rdoctask'

spec = Gem::Specification.new do |s|
  s.name     = 'denyspam'
  s.version  = '1.0.0'
  s.author   = 'Ryan Grove'
  s.email    = 'ryan@wonko.com'
  s.homepage = 'http://wonko.com/software/denyspam'
  s.platform = Gem::Platform::RUBY
  s.summary  = "Monitors a mail server log file and uses Packet Filter to " +
               "temporarily block or redirect incoming packets from hosts " +
               "that display spammer-like behavior."
  
  s.rubyforge_project = 'denyspam'

  s.files        = FileList['{bin,lib}/**/*', 'LICENSE', 'HISTORY'].exclude('rdoc').to_a
  s.executables  = ['denyspam']
  s.require_path = 'lib'

  s.has_rdoc         = true
  s.extra_rdoc_files = ['README', 'LICENSE']
  s.rdoc_options << '--title' << 'DenySpam Documentation' <<
                    '--main' << 'README' <<
                    '--line-numbers'

  s.required_ruby_version = '>= 1.8.4'
end

Rake::GemPackageTask.new(spec) do |pkg|
  pkg.need_tar = true
end

Rake::RDocTask.new do |rd|
  rd.main     = 'README'
  rd.title    = 'DenySpam Documentation'
  rd.rdoc_dir = 'doc/html'
  rd.rdoc_files.include('README', 'bin/**/*', 'lib/**/*.rb')
end
