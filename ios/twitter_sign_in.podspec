Pod::Spec.new do |s|
  s.name             = 'twitter_sign_in'
  s.version          = '5.0.2'
  s.summary          = 'Flutter Twitter Sign In Plugin'
  s.description      = <<-DESC
A Flutter plugin for signing in with Twitter.
                       DESC
  s.homepage         = 'https://github.com/jayfinava-benzatine/twitter_sign_in'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Your Company' => 'email@example.com' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform         = :ios, '11.0'

  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'VALID_ARCHS[sdk=iphonesimulator*]' => 'x86_64' }
  s.swift_version    = '5.0'
end
