# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require 'digest'

class LogStash::Filters::GoogleAppengine < LogStash::Filters::Base

  config_name "google_appengine"

  public
  def register
    @md5 = Digest::MD5.new
  end

  public
  def filter(event)
    return unless filter?(event)

    payload = event['protoPayload']
    payload.delete '@type'
    lines = payload.delete 'line'
    if lines
      lines.each_with_index { |line, i|
        next if line.empty?
        line_data = {}

        line_data = line_data.merge(payload)
        line_data = line_data.merge(line)
        line_data['_id'] = @md5.hexdigest line_data['requestId'] + i.to_s
        line_data['message'] = line_data.delete 'logMessage'
        line_data.delete 'logMessage'

        new_event = LogStash::Event::new(line_data)
        filter_matched(new_event)
        yield(new_event)
      }
    else
      payload['_id'] = @md5.hexdigest payload['requestId']
      payload['time'] = payload['endTime']

      new_event = LogStash::Event::new(payload)
      filter_matched(new_event)

      yield new_event
    end

    event.cancel
  end
end
