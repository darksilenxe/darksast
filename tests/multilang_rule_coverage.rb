system(user_input)
Digest::MD5.hexdigest(data)
YAML.load(data)
OpenSSL::SSL::VERIFY_NONE

# CSRF: disabling Rails CSRF protections.
class UnsafeController < ApplicationController
  skip_before_action :verify_authenticity_token
  protect_from_forgery with: :null_session
end
