require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/google_appengine"
require "logstash/json"

describe LogStash::Filters::GoogleAppengine do

  config <<-CONFIG
        filter {
          google_appengine { }
         }
  CONFIG

  describe "should merge the request payload with the request lines data" do
    test_sample = LogStash::Json::load(File.open("spec/filters/appengine.logs.json", "rb").read)
    sample (test_sample) do
      insist { subject.length } == 3

      insist { subject[0].get("message") }=="IdentityFilter logUserIdentity: [[meta]] <anonymous:true>\n"
      insist { subject[0].get("id") }== subject[0].get("requestId") + "0"
      insist { subject[0].get("time") } == "2015-09-03T10:59:40.589Z"
      insist { subject[0].get("position") } == 0
      insist { subject[0].get("@type") } == nil

      insist { subject[1].get("message") }=="HttpOnlyFilter getSession: add additional Set-Cookie with httpOnly-flag for JSESSIONID\n"
      insist { subject[1].get("id") } == subject[1].get("requestId") + "1"
      insist { subject[1].get("@type") } == nil
      insist { subject[1].get("time") } =="2015-09-03T10:59:40.65Z"
      insist { subject[1].get("position") } == 1
    end
  end

  describe "should readv2 log data" do
    test_sample = LogStash::Json::load(File.open("spec/filters/appengine.logs-v2.json", "rb").read)
    sample (test_sample) do
      insist { subject.length } == 13

      insist { subject[0].get("message") }=="IdentityContextLogger logUserAndHisProperties: [Identity][BEGIN] userId:userId userMail:e@mail.com companyId:companyId isSI:false\n"
      insist { subject[0].get("id") }== subject[0].get("requestId") + "0"
      insist { subject[0].get("time") } == "2017-02-20T00:59:59.265Z"
      insist { subject[0].get("position") } == 0
      insist { subject[0].get("@type") } == nil

      insist { subject[1].get("message") } == "StoreReviewJSON init: e@mail.com ( user ) is viewing StoreReviewJSON\n"
      insist { subject[1].get("id") } == subject[1].get("requestId") + "1"
      insist { subject[1].get("@type") } == nil
      insist { subject[1].get("time") } =="2017-02-20T00:59:59.277Z"
      insist { subject[1].get("position") } == 1
    end
  end


  describe "should handle logs even when they have no lines" do
    test_sample = LogStash::Json.load(File.open("spec/filters/appengine.logs-without-lines.json", "rb").read)
    sample (test_sample) do

      insist { subject.get("resource") } == "/images/website/welcome/keyFeatures/objectives.jpg"
      insist { subject.get("id") } == subject.get("requestId")
      insist { subject.get("time") } == subject.get("endTime")
      insist { subject.get("@type") } == nil
    end
  end

  describe "should convert latency (string) to latencyS (number)" do
    test_sample = LogStash::Json.load(File.open("spec/filters/log-with-pendingTime.json", "rb").read)
    sample (test_sample) do
      insist { subject[0].get("latency") } == "0.779603s"
      insist { subject[0].get("latencyS") } == 0.779603
    end
  end

  describe "should convert pendingTime (string) to pendingTimeS (number)" do
    test_sample = LogStash::Json.load(File.open("spec/filters/log-with-pendingTime.json", "rb").read)
    sample (test_sample) do
      insist { subject[0].get("pendingTime") } == "0.712152958s"
      insist { subject[0].get("pendingTimeS") } == 0.712152958
    end
  end

  describe "should convert missing pendingTime to pendingTimeS is 0" do
    test_sample = LogStash::Json.load(File.open("spec/filters/log-without-pendingTime.json", "rb").read)
    sample (test_sample) do
      insist { subject[0].get("pendingTime") } == nil
      insist { subject[0].get("pendingTimeS") } == 0
    end
  end

  describe "should calculate appTimeS from latencyS and pendingTimeS" do
    test_sample = LogStash::Json.load(File.open("spec/filters/log-with-pendingTime.json", "rb").read)
    sample (test_sample) do
      insist { subject[0].get("appTimeS") } == 0.779603 - 0.712152958
    end
  end

end


