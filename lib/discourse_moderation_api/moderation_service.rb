# frozen_string_literal: true

module ::DiscourseModerationApi
  class ModerationService
    def self.analyze_post(post)
      Rails.logger.debug("Analyzing post content")

      topic_title = nil
      topic_title = post.topic.title if post.post_number == 1

      analyze_content(
        content: post.raw,
        author_id: post.user_id.to_s,
        context_id: post.topic_id.to_s,
        content_id: post.id&.to_s || "pending_#{Time.now.to_i}",
        content_url:
          "#{Discourse.base_url}/t/#{post.topic.slug}/#{post.topic_id}/#{post.post_number}",
        topic_title: topic_title,
      )
    end

    private

    def self.analyze_content(
      content:,
      author_id:,
      context_id:,
      content_id:,
      content_url:,
      topic_title:
    )
      Rails.logger.info("Analyzing content with Aliyun Moderation API")

      begin
        # 图片审核部分
        doc = Nokogiri::HTML5.fragment(PrettyText.cook(content))
        image_urls = doc.css("img").map { |img| img["src"] }.compact

        image_urls.each do |url|
          full_url = url.start_with?("http") ? url : "#{Discourse.base_url}#{url}"
          Rails.logger.debug("Checking image: #{full_url.truncate(100)}")

          response = aliyun_image_moderation(full_url)
          next if response[:approved]

          Rails.logger.warn("Image moderation failed for URL: #{full_url.truncate(100)}")
          return { approved: false }
        end

        # 文本审核预留接口
        # analyze_text_content(content)

        { approved: true }
      rescue => e
        Rails.logger.error("Unexpected error in moderation service: #{e.message}")
        Rails.logger.error(e.backtrace.join("\n"))
        { approved: true }
      end
    end

    def self.aliyun_image_moderation(image_url)
      access_key_id = SiteSetting.aliyun_access_key_id
      access_key_secret = SiteSetting.aliyun_access_key_secret
      region = SiteSetting.aliyun_region || "cn-shanghai"

      # 公共请求参数
      params = {
        "Action" => "ImageModeration",
        "Version" => "2022-03-02",
        "AccessKeyId" => access_key_id,
        "Format" => "JSON",
        "SignatureMethod" => "HMAC-SHA1",
        "Timestamp" => Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "SignatureVersion" => "1.0",
        "SignatureNonce" => SecureRandom.uuid,
        "Service" => "baselineCheck",
        "ServiceParameters" => { imageUrl: image_url }.to_json,
      }

      # 生成规范化的查询字符串
      canonicalized_params =
        params
          .sort
          .map { |key, value| "#{CGI.escape(key.to_s)}=#{CGI.escape(value.to_s)}" }
          .join("&")
          .gsub(/\+/, "%20")

      # 生成签名
      string_to_sign = "POST&%2F&#{CGI.escape(canonicalized_params)}"
      hmac = OpenSSL::HMAC.digest("sha1", "#{access_key_secret}&", string_to_sign)
      signature = Base64.strict_encode64(hmac)
      params["Signature"] = signature

      # 构造请求
      uri = URI("https://green-cip.#{region}.aliyuncs.com")
      uri.query = URI.encode_www_form(params)

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      request = Net::HTTP::Post.new(uri)
      request["Content-Type"] = "application/x-www-form-urlencoded"

      # 发送请求
      response = http.request(request)
      json_response = JSON.parse(response.body)
      Rails.logger.info("Aliyun API resp: #{json_response}")
      # 根据实际响应结构调整以下判断逻辑
      if json_response && (response.code.to_i >= 200 && response.code.to_i < 300)
        risk_level = json_response.dig("Data", "RiskLevel")&.downcase
        
        # 从配置读取允许的等级列表
        allowed_levels = SiteSetting.aliyun_risk_level_allow_list.split(',').map(&:downcase)
        Rails.logger.debug("RiskLevel: #{risk_level} | Allowed: #{allowed_levels}")
        # 动态判断
        if risk_level && allowed_levels.include?(risk_level)
          approved = true
        else
          # 等级不明确时的默认处理
          default_decision = allowed_levels.exclude?('medium') && allowed_levels.exclude?('high')
          approved = (risk_level.blank? ? default_decision : false)
        end
      else
        # ...错误处理保持不变...
      end
      { approved: approved }
    rescue => e
      Rails.logger.error("Aliyun API error: #{e.message}")
      { approved: true } # 失败时默认通过
    end

    # 预留文本审核方法
    # def self.analyze_text_content(content)
    #   # Todo: 实现文本审核逻辑
    # end
  end
end
