# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require 'digest'

class LogStash::Filters::GoogleAppengine < LogStash::Filters::Base

  config_name "google_appengine"

  public
  def register
    @md5 = Digest::MD5.new
    @semaphore = Mutex.new
  end

  def filter(event)
    return unless filter?(event)
    return unless event['protoPayload']

    payload = event['protoPayload']
    payload.delete '@type'
    payload['type'] = event['type']
    payload['latencyInt'] = payload['latency'].delete("s").to_f

    lines = payload.delete 'line'

    if lines
      lines.each_with_index { |line, i|
        yield create_event(collect_line_data(i, line, payload))
      }
    else
      yield create_event(collect_resource_request_data(payload))
    end
    event.cancel
  end

  private
  # noinspection RubyStringKeysInHashInspection
  def collect_line_data(i, line, payload)
    {
        'id' => get_id(payload['requestId'] + i.to_s),
        'message' => line.delete('logMessage'),
        'position' => i
    }
        .merge(payload)
        .merge(line)
  end

  # noinspection RubyStringKeysInHashInspection
  def collect_resource_request_data(payload)
    {
        'id' => get_id(payload['requestId']),
        'time' => payload['endTime'],
        'position' => 0
    }
        .merge(payload)
  end

  def create_event(payload)
    new_event = LogStash::Event::new(payload)
    filter_matched(new_event)
    new_event
  end

  def get_id(source)
    @semaphore.synchronize {
      @md5.hexdigest(source)  #md5 isn't threadsafe :(
    }
  end

end # class LogStash::Filters::GoogleAppengine
