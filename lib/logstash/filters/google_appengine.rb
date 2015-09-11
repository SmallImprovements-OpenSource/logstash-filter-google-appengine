# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require 'digest'

class LogStash::Filters::GoogleAppengine < LogStash::Filters::Base

  config_name "google_appengine"

  public
  def register
    @md5 = Digest::MD5.new
  end  # def register

  public
  def filter(event)
    return unless filter?(event)

    payload = event['protoPayload']
    payload.delete '@type'
    payload['type'] = 'gae'
    lines = payload.delete 'line'

    if lines
      lines.each_with_index { |line, i|
        # noinspection RubyStringKeysInHashInspection
        line_data = {
            '_id' => @md5.hexdigest(payload['requestId'] + i.to_s),
            'message' => line.delete('logMessage')
        }
                        .merge(payload)
                        .merge(line)

        yield create_event(line_data)

      }
    else
      payload['_id'] = @md5.hexdigest payload['requestId']
      payload['time'] = payload['endTime']
      yield create_event(payload)
    end
    event.cancel
  end # def filter

  private
  def create_event(payload)
    new_event = LogStash::Event::new(payload)
    filter_matched(new_event)
    new_event
  end # def filter

end # class LogStash::Filters::GoogleAppengine
