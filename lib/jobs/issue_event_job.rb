require 'time'

class IssueEventJob
  include SuckerPunch::Job

  def perform(payload)
    if ENV["SOCKET_BACKEND"]
      begin
        Faraday.post do |req|
          req.url "#{ENV["SOCKET_BACKEND"]}/hook"
          #req.url "http://requestb.in/1d0hd3s1"
          req.headers['Content-Type'] = 'application/json'
          req.body = payload.merge({secret: ENV["SOCKET_SECRET"]}).to_json
        end
      rescue
      end
    end
    #PublishWebhookJob.new.publish payload
  rescue
  end

  def production?
    ENV["RACK_ENV"] == "production" || ENV["RACK_ENV"] == "staging" 
  end

  def execute payload
    if production?
      async.perform payload 
    else
      perform payload
    end
  end
end

class PublishWebhookJob
  include SuckerPunch::Job

  def couch
    @couch ||= Huboard::Couch.new :base_url => ENV["COUCH_URL"], :database => ENV["COUCH_DATABASE"]
  end

  def perform payload
    full_name = payload[:meta][:repo_full_name]

    result = couch.integrations.by_full_name "\"#{CGI.escape(full_name.gsub("/","-"))}\""

    result.rows.each do |r| 
      begin
        Faraday.post do |req|
          req.url r.value.integration.webhook_url
          req.headers['Content-Type'] = 'application/json'
          req.body = payload.to_json
        end
      rescue
      end
    end

  end

  def production?
    ENV["RACK_ENV"] == "production" || ENV["RACK_ENV"] == "staging" 
  end

  def publish payload
    if production?
      async.perform payload 
    else
      perform payload
    end
  end
end

class IssueMovedEvent < IssueEventJob
  def publish(issue, previous, user, correlationId = "")
    payload = {
      meta: {
        action: "moved",
        identifier: issue.number,
        timestamp: Time.now.utc.iso8601,
        user: user,
        correlationId: correlationId,
        repo_full_name: "#{issue.repo.owner.login}/#{issue.repo.name}"
      },
      payload: {
        issue: issue,
        column: issue.current_state,
        previous: previous
      }
    }

    execute payload
  end
end

class IssueReorderedEvent < IssueEventJob
  def publish(issue, user, correlationId = "")
    payload = {
      meta: {
        action: "reordered",
        identifier: issue.number,
        timestamp: Time.now.utc.iso8601,
        user: user,
        correlationId: correlationId,
        repo_full_name: "#{issue.repo.owner.login}/#{issue.repo.name}"
      },
      payload: {
        issue: issue,
        column: issue.current_state
      }
    }

    execute payload
  end
end

class IssueAssignedEvent < IssueEventJob
  def publish(issue, user, correlationId = "")
    payload = {
      meta: {
        action: "assigned",
        identifier: issue.number,
        timestamp: Time.now.utc.iso8601,
        user: user,
        correlationId: correlationId,
        repo_full_name: "#{issue.repo.owner.login}/#{issue.repo.name}"
      },
      payload: {
        issue: issue,
        assignee: issue.assignee
      }
    }

    execute payload
  end
end

class IssueMilestoneChangedEvent < IssueEventJob
  def publish(issue, user, correlationId = "")
    payload = {
      meta: {
        action: "milestone_changed",
        identifier: issue.number,
        timestamp: Time.now.utc.iso8601,
        user: user,
        correlationId: correlationId,
        repo_full_name: "#{issue.repo.owner.login}/#{issue.repo.name}"
      },
      payload: {
        issue: issue,
        milestone: issue.milestone
      }
    }

    execute payload
  end
end

class IssueClosedEvent < IssueEventJob
  def publish(issue, user, correlationId = "")
    payload = {
      meta: {
        action: "issue_closed",
        identifier: issue.number,
        timestamp: Time.now.utc.iso8601,
        user: user,
        correlationId: correlationId,
        repo_full_name: "#{issue.repo.owner.login}/#{issue.repo.name}"
      },
      payload: {
        issue: issue
      }
    }

    execute payload
  end
end

class IssueOpenedEvent < IssueEventJob
  def publish(issue, user, correlationId = "")
    payload = {
      meta: {
        action: "issue_opened",
        identifier: issue.number,
        timestamp: Time.now.utc.iso8601,
        user: user,
        correlationId: correlationId,
        repo_full_name: "#{issue.repo.owner.login}/#{issue.repo.name}"
      },
      payload: {
        issue: issue
      }
    }

    execute payload
  end
end

class IssueReopenedEvent < IssueEventJob
  def publish(issue, user, correlationId = "")
    payload = {
      meta: {
        action: "issue_reopened",
        identifier: issue.number,
        timestamp: Time.now.utc.iso8601,
        user: user,
        correlationId: correlationId,
        repo_full_name: "#{issue.repo.owner.login}/#{issue.repo.name}"
      },
      payload: {
        issue: issue
      }
    }

    execute payload
  end
end




