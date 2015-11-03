require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/google_appengine"
require "logstash/json"
require 'digest'

describe LogStash::Filters::GoogleAppengine do

  md5 = Digest::MD5.new

  config <<-CONFIG
        filter {
          google_appengine { }
         }
  CONFIG

  describe "should merge the request payload with the reuest lines data" do
    test_sample = LogStash::Json::load(File.open("spec/filters/appengine.logs.jsonl", "rb").read)
    sample (test_sample) do
      insist { subject.length } == 3

      insist { subject[0]["message"] }=="IdentityFilter logUserIdentity: [[meta]] <anonymous:true>\n"
      insist { subject[0]["id"] }== md5.hexdigest(subject[0]["requestId"] + "0")
      insist { subject[0]["time"] } == "2015-09-03T10:59:40.589Z"
      insist { subject[0]["position"] } == 0
      insist { subject[0]["@type"] } == nil

      insist { subject[1]["message"] }=="HttpOnlyFilter getSession: add additional Set-Cookie with httpOnly-flag for JSESSIONID\n"
      insist { subject[1]["id"] } == md5.hexdigest(subject[1]["requestId"] + "1")
      insist { subject[1]["@type"] } == nil
      insist { subject[1]["time"] } =="2015-09-03T10:59:40.65Z"
      insist { subject[1]["position"] } == 1
    end
  end

  describe "should handle logs even when they have no lines" do
    test_sample = LogStash::Json.load(File.open("spec/filters/appengine.logs-without-lines.jsonl", "rb").read)
    sample (test_sample) do

      insist { subject["resource"] } == "/images/website/welcome/keyFeatures/objectives.jpg"
      insist { subject["id"] } == md5.hexdigest(subject["requestId"])
      insist { subject["time"] } == subject["endTime"]
      insist { subject["@type"] } == nil
    end
  end
end


