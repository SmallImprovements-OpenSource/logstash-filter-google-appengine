Gem::Specification.new do |s|

  s.name = 'logstash-filter-google_appengine'
  s.version = '0.121.0'
  s.licenses = ['Apache License (2.0)']
  s.summary = "This filter may be used to decode via inputs appengine logs"
  s.description = "This gem is a logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/plugin install gemname. This gem is not a stand-alone program"
  s.authors = ["Small Improvements"]
  s.email = 'mruhwedel@small-improvements.com'
  s.homepage = "https://github.com/SmallImprovements/logstash-filter-google_appengine"
  s.require_paths = ["lib"]

  s.files = `git ls-files`.split($\)

  s.test_files = s.files.grep(%r{^spec/})

  s.metadata = {"logstash_plugin" => "true", "logstash_group" => "filter"}

  s.add_runtime_dependency "logstash-core-plugin-api", ">= 1.60", "<= 2.99"

  s.add_development_dependency 'logstash-devutils'

end

