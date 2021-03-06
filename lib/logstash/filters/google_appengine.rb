# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

class LogStash::Filters::GoogleAppengine < LogStash::Filters::Base

  config_name "google_appengine"

  public

  def register
  end

  def filter(event)
    return unless filter?(event)
    return unless event.get('protoPayload')

    payload = event.get('protoPayload')
    payload.delete '@type'
    payload['type'] = event.get('type')
    payload['latencyS'] = to_number(payload['latency'])
    payload['pendingTimeS'] = to_number(payload['pendingTime'])
    payload['appTimeS'] = payload['latencyS'] - payload['pendingTimeS']
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
  def to_number(string)
    string ? string.delete("s").to_f : 0.0
  end

  def collect_line_data(i, line, payload)
    {
        'id' => (payload['requestId'] + i.to_s),
        'message' => line.delete('logMessage'),
        'position' => i
    }
        .merge(payload)
        .merge(line)
  end

  # noinspection RubyStringKeysInHashInspection
  def collect_resource_request_data(payload)
    {
        'id' => payload['requestId'],
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

end # class LogStash::Filters::GoogleAppengine
