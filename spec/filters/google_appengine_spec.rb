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
    test_sample = LogStash::Json::load(File.open("spec/filters/appengine.logs.json", "rb").read)
    sample (test_sample) do
      LATENCY_OF_REQUEST = 0.115752
      insist { subject.length } == 3

      insist { subject[0].get("message") }=="IdentityFilter logUserIdentity: [[meta]] <anonymous:true>\n"
      insist { subject[0].get("id") }== md5.hexdigest(subject[0].get("requestId") + "0")
      insist { subject[0].get("time") } == "2015-09-03T10:59:40.589Z"
      insist { subject[0].get("position") } == 0
      insist { subject[0].get("@type") } == nil
      insist { subject[0].get("latencyS") } == LATENCY_OF_REQUEST
      insist { subject[0].get("pendingTimeS") } == nil

      insist { subject[1].get("message") }=="HttpOnlyFilter getSession: add additional Set-Cookie with httpOnly-flag for JSESSIONID\n"
      insist { subject[1].get("id") } == md5.hexdigest(subject[1].get("requestId") + "1")
      insist { subject[1].get("@type") } == nil
      insist { subject[1].get("time") } =="2015-09-03T10:59:40.65Z"
      insist { subject[1].get("position") } == 1
      insist { subject[0].get("pendingTimeS") } == nil
    end
  end

  describe "should handle logs even when they have no lines" do
    test_sample = LogStash::Json.load(File.open("spec/filters/appengine.logs-without-lines.json", "rb").read)
    sample (test_sample) do

      insist { subject.get("resource") } == "/images/website/welcome/keyFeatures/objectives.jpg"
      insist { subject.get("id") } == md5.hexdigest(subject.get("requestId"))
      insist { subject.get("time") } == subject.get("endTime")
      insist { subject.get("@type") } == nil
    end
  end
end


